#include "ui.h"

#include <cstdio>
#include <cstring>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <string>

#include "display.h"
#include "board_tdisplay.h"
#include "find_my_outbox.hpp"
#include "unit.hpp"
#include "wallet_store.hpp"
#include "wifi.h"

namespace {

#if !CONFIG_BOARD_HELTEC_V3
void draw_title_bar(const char *right_label)
{
    display_fill_rect(0, 0, LCD_W, 13, COLOR_WHITE);
    display_text_color(3, 3, "FIND MY NUTS", COLOR_BLACK, COLOR_WHITE, 1);
    if (right_label && right_label[0]) {
        int rx = LCD_W - display_text_width(right_label, 1) - 3;
        display_text_color(rx, 3, right_label, COLOR_BLACK, COLOR_WHITE, 1);
    }
}

const char *trim_scheme(const char *url)
{
    if (strncmp(url, "https://", 8) == 0) return url + 8;
    if (strncmp(url, "http://", 7) == 0) return url + 7;
    return url;
}
#endif

void draw_power_indicator(const board_tdisplay_power_status_t &power)
{
    constexpr int y = LCD_H - 11;
    constexpr int battery_w = 13;
    constexpr int battery_h = 8;

    if (power.source == BOARD_TDISPLAY_POWER_USB) {
        const char *label = "USB";
        display_text(LCD_W - display_text_width(label, 1) - 3, y, label, 1);
        return;
    }
    if (power.source != BOARD_TDISPLAY_POWER_BATTERY) {
        const char *label = "PWR?";
        display_text(LCD_W - display_text_width(label, 1) - 3, y, label, 1);
        return;
    }

    // Five-percent text steps keep ADC noise from making the footer flicker.
    const unsigned display_percent =
        power.percent >= 98 ? 100 : ((power.percent + 2U) / 5U) * 5U;
    char label[6];
    snprintf(label, sizeof(label), "%u%%", display_percent);
    const int label_w = display_text_width(label, 1);
    const int icon_x = LCD_W - 3 - label_w - 3 - battery_w;

    // Monochrome battery silhouette: outline, positive terminal, and a fill
    // proportional to the estimated percentage. Text keeps state accessible.
    display_fill_rect(icon_x, y, battery_w - 2, 1, COLOR_WHITE);
    display_fill_rect(icon_x, y + battery_h - 1, battery_w - 2, 1, COLOR_WHITE);
    display_fill_rect(icon_x, y, 1, battery_h, COLOR_WHITE);
    display_fill_rect(icon_x + battery_w - 3, y, 1, battery_h, COLOR_WHITE);
    display_fill_rect(icon_x + battery_w - 2, y + 2, 2, battery_h - 4,
                      COLOR_WHITE);
    const int fill_w = static_cast<int>((display_percent * 8U + 50U) / 100U);
    if (fill_w > 0)
        display_fill_rect(icon_x + 2, y + 2, fill_w, battery_h - 4,
                          COLOR_WHITE);
    display_text(icon_x + battery_w + 1, y, label, 1);
}

} // namespace

void display_refresh()
{
    board_tdisplay_power_status_t power = {};
    (void)board_tdisplay_power_read(&power);

    // Never hard-block the UI on mint/TLS operations. Command handlers call
    // display_refresh() again and the periodic UI task self-heals skipped
    // frames. The recursive store mutex lets a command refresh while guarded.
    if (!wallet_store_try_lock(50))
        return;

    display_clear();

    const auto fm = find_my_nuts::outbox_status();
#if CONFIG_BOARD_HELTEC_V3
    // Five fixed rows keep the 128x64 OLED legible. The battery owns the
    // footer's right edge, with no overlapping wallet or message text.
    char radio[22];
    if (!fm.initialized || !fm.reconciled || !fm.started)
        snprintf(radio, sizeof(radio), "Find My stopped");
    else if (fm.paused)
        snprintf(radio, sizeof(radio), "%s", fm.has_active_message ? "Find My ready" : "Find My off");
    else if (fm.transmitting && fm.total_symbols)
        snprintf(radio, sizeof(radio), "Find My %u%%",
                 (unsigned)(fm.current_symbol * 100U / fm.total_symbols));
    else
        snprintf(radio, sizeof(radio), "Find My starting");
    display_text(2, 2, radio, 1);
    display_hline(2, 12, LCD_W - 4);
    const std::string unit = cashu::Wallet::default_unit();
    char balance[36];
    cashu::format_amount(balance, sizeof(balance),
                        wallet_store_balance_for_unit(unit.c_str()), unit.c_str());
    int scale = display_text_width(balance, 2) <= LCD_W - 4 ? 2 : 1;
    display_text(2, 17, balance, scale);
    char message[24];
    if (fm.transmitting || fm.has_active_message)
        snprintf(message, sizeof(message), "msg:%lu %s",
                 (unsigned long)(fm.transmitting ? fm.current_message_id : fm.active_message_id),
                 wifi_is_connected() ? "WiFi" : "offline");
    else
        snprintf(message, sizeof(message), "%s  %u/%u out",
                 wifi_is_connected() ? "WiFi" : "offline",
                 (unsigned)fm.used_slots, (unsigned)fm.capacity);
    display_text(2, 37, message, 1);
    display_text(2, LCD_H - 11, "PRG hold 1s", 1);
    draw_power_indicator(power);
    wallet_store_unlock();
    display_update();
#else
    char radio[24];
    if (!fm.initialized || !fm.reconciled || !fm.started) {
        snprintf(radio, sizeof(radio), "FM STOP");
    } else if (fm.paused && fm.has_active_message) {
        snprintf(radio, sizeof(radio), "FM READY");
    } else if (fm.paused) {
        // The durable manual gate is authoritative even while the current GAP
        // dwell cooperatively winds down after cancellation.
        snprintf(radio, sizeof(radio), "FM OFF");
    } else if (fm.transmitting && fm.total_symbols > 0) {
        unsigned percent = (unsigned)(fm.current_symbol * 100U / fm.total_symbols);
        snprintf(radio, sizeof(radio), "FM %u%%", percent);
    } else if (fm.used_slots > 0) {
        snprintf(radio, sizeof(radio), "%s FM:%u",
                 wifi_is_connected() ? "W" : "-", (unsigned)fm.used_slots);
    } else {
        snprintf(radio, sizeof(radio), "%s FM ON",
                 wifi_is_connected() ? "W" : "-");
    }
    draw_title_bar(radio);

    const std::string default_unit = cashu::Wallet::default_unit();
    long long default_balance = wallet_store_balance_for_unit(default_unit.c_str());
    int total_proofs = 0;
    for (int i = 0; i < MAX_MINTS; ++i) {
        auto *wallet = wallet_store_get(i);
        if (wallet) total_proofs += (int)wallet->proofs().size();
    }

    char amount[40];
    cashu::format_amount_value(amount, sizeof(amount), default_balance,
                               default_unit.c_str());
    int balance_scale = 4;
    while (balance_scale > 1
           && display_text_width(amount, balance_scale) > LCD_W - 8)
        --balance_scale;
    int amount_x = (LCD_W - display_text_width(amount, balance_scale)) / 2;
    display_text(amount_x < 0 ? 0 : amount_x, 20, amount, balance_scale);

    int unit_x = (LCD_W - display_text_width(default_unit.c_str(), 1)) / 2;
    display_text(unit_x < 0 ? 0 : unit_x, 56, default_unit.c_str(), 1);
    display_hline(3, 70, LCD_W - 6);

    // Three compact wallet rows fit without sacrificing the status line.
    int row_y = 77;
    int shown = 0;
    for (int i = 0; i < MAX_MINTS && shown < 3; ++i) {
        auto *wallet = wallet_store_get(i);
        if (!wallet) continue;

        char wallet_amount[24];
        cashu::format_amount_value(wallet_amount, sizeof(wallet_amount),
                                   wallet->balance_for_unit(default_unit),
                                   default_unit.c_str());
        int amount_right = LCD_W - display_text_width(wallet_amount, 1) - 3;
        int max_url_chars = (amount_right - 10) / 6;
        if (max_url_chars < 1) max_url_chars = 1;

        char mint_label[40];
        snprintf(mint_label, sizeof(mint_label), "%d %.*s", i,
                 max_url_chars, trim_scheme(wallet->mint_url().c_str()));
        display_text(3, row_y, mint_label, 1);
        display_text(amount_right, row_y, wallet_amount, 1);
        row_y += 11;
        ++shown;
    }
    if (shown == 0)
        display_text(3, 82, "console: mint add <url>", 1);

    char footer[36];
    if (fm.transmitting) {
        snprintf(footer, sizeof(footer), "%dp  msg:%lu",
                 total_proofs, (unsigned long)fm.current_message_id);
    } else if (fm.has_active_message) {
        snprintf(footer, sizeof(footer), "%dp  armed:%lu",
                 total_proofs, (unsigned long)fm.active_message_id);
    } else {
        snprintf(footer, sizeof(footer), "%dp  out:%u/%u",
                 total_proofs, (unsigned)fm.used_slots, (unsigned)fm.capacity);
    }
    display_text(3, 124, footer, 1);
    draw_power_indicator(power);

    wallet_store_unlock();
    display_update();
#endif
}

void display_ui_task(void *)
{
    for (;;) {
        display_refresh();
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}
