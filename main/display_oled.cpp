#include "display.h"
#include "board_tdisplay.h"

#include <cstring>
#include <driver/i2c_master.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

namespace {
constexpr int kTransferTimeoutMs = 100;
i2c_master_bus_handle_t s_bus;
i2c_master_dev_handle_t s_oled;
SemaphoreHandle_t s_lock;
uint8_t s_fb[LCD_W * ((LCD_H + 7) / 8)];
bool s_initialized;
bool s_powered;

void lock_display()
{
    if (s_lock) xSemaphoreTakeRecursive(s_lock, portMAX_DELAY);
}
void unlock_display()
{
    if (s_lock) xSemaphoreGiveRecursive(s_lock);
}
void pixel_locked(int x, int y, bool on)
{
    if (x < 0 || x >= LCD_W || y < 0 || y >= LCD_H) return;
    auto &byte = s_fb[(y >> 3) * LCD_W + x];
    if (on) byte |= 1U << (y & 7);
    else byte &= ~(1U << (y & 7));
}
bool command(uint8_t value)
{
    const uint8_t packet[] = {0x00, value};
    return i2c_master_transmit(s_oled, packet, sizeof(packet),
                               kTransferTimeoutMs) == ESP_OK;
}
bool flush_locked()
{
    for (int page = 0; page < LCD_H / 8; ++page) {
        if (!command(0xB0 | page) || !command(0x00) || !command(0x10))
            return false;
        for (int x = 0; x < LCD_W; x += 32) {
            uint8_t packet[33] = {0x40};
            memcpy(packet + 1, s_fb + page * LCD_W + x, 32);
            if (i2c_master_transmit(s_oled, packet, sizeof(packet),
                                    kTransferTimeoutMs) != ESP_OK)
                return false;
        }
    }
    return true;
}
void power_locked(bool on)
{
    if (!s_initialized || s_powered == on) return;
    if (on) {
        // Restore RAM before lighting the panel, so no stale frame flashes.
        if (!flush_locked()) return;
    }
    if (command(on ? 0xAF : 0xAE)) s_powered = on;
}
} // namespace

static const uint8_t font5x7[][5] = {
    {0x00,0x00,0x00,0x00,0x00}, // 32 space
    {0x00,0x00,0x5F,0x00,0x00}, // 33 !
    {0x00,0x07,0x00,0x07,0x00}, // 34 "
    {0x14,0x7F,0x14,0x7F,0x14}, // 35 #
    {0x24,0x2A,0x7F,0x2A,0x12}, // 36 $
    {0x23,0x13,0x08,0x64,0x62}, // 37 %
    {0x36,0x49,0x55,0x22,0x50}, // 38 &
    {0x00,0x05,0x03,0x00,0x00}, // 39 '
    {0x00,0x1C,0x22,0x41,0x00}, // 40 (
    {0x00,0x41,0x22,0x1C,0x00}, // 41 )
    {0x08,0x2A,0x1C,0x2A,0x08}, // 42 *
    {0x08,0x08,0x3E,0x08,0x08}, // 43 +
    {0x00,0x50,0x30,0x00,0x00}, // 44 ,
    {0x08,0x08,0x08,0x08,0x08}, // 45 -
    {0x00,0x60,0x60,0x00,0x00}, // 46 .
    {0x20,0x10,0x08,0x04,0x02}, // 47 /
    {0x3E,0x51,0x49,0x45,0x3E}, // 48 0
    {0x00,0x42,0x7F,0x40,0x00}, // 49 1
    {0x42,0x61,0x51,0x49,0x46}, // 50 2
    {0x21,0x41,0x45,0x4B,0x31}, // 51 3
    {0x18,0x14,0x12,0x7F,0x10}, // 52 4
    {0x27,0x45,0x45,0x45,0x39}, // 53 5
    {0x3C,0x4A,0x49,0x49,0x30}, // 54 6
    {0x01,0x71,0x09,0x05,0x03}, // 55 7
    {0x36,0x49,0x49,0x49,0x36}, // 56 8
    {0x06,0x49,0x49,0x29,0x1E}, // 57 9
    {0x00,0x36,0x36,0x00,0x00}, // 58 :
    {0x00,0x56,0x36,0x00,0x00}, // 59 ;
    {0x00,0x08,0x14,0x22,0x41}, // 60 <
    {0x14,0x14,0x14,0x14,0x14}, // 61 =
    {0x41,0x22,0x14,0x08,0x00}, // 62 >
    {0x02,0x01,0x51,0x09,0x06}, // 63 ?
    {0x32,0x49,0x79,0x41,0x3E}, // 64 @
    {0x7E,0x11,0x11,0x11,0x7E}, // 65 A
    {0x7F,0x49,0x49,0x49,0x36}, // 66 B
    {0x3E,0x41,0x41,0x41,0x22}, // 67 C
    {0x7F,0x41,0x41,0x22,0x1C}, // 68 D
    {0x7F,0x49,0x49,0x49,0x41}, // 69 E
    {0x7F,0x09,0x09,0x01,0x01}, // 70 F
    {0x3E,0x41,0x41,0x51,0x32}, // 71 G
    {0x7F,0x08,0x08,0x08,0x7F}, // 72 H
    {0x00,0x41,0x7F,0x41,0x00}, // 73 I
    {0x20,0x40,0x41,0x3F,0x01}, // 74 J
    {0x7F,0x08,0x14,0x22,0x41}, // 75 K
    {0x7F,0x40,0x40,0x40,0x40}, // 76 L
    {0x7F,0x02,0x04,0x02,0x7F}, // 77 M
    {0x7F,0x04,0x08,0x10,0x7F}, // 78 N
    {0x3E,0x41,0x41,0x41,0x3E}, // 79 O
    {0x7F,0x09,0x09,0x09,0x06}, // 80 P
    {0x3E,0x41,0x51,0x21,0x5E}, // 81 Q
    {0x7F,0x09,0x19,0x29,0x46}, // 82 R
    {0x46,0x49,0x49,0x49,0x31}, // 83 S
    {0x01,0x01,0x7F,0x01,0x01}, // 84 T
    {0x3F,0x40,0x40,0x40,0x3F}, // 85 U
    {0x1F,0x20,0x40,0x20,0x1F}, // 86 V
    {0x7F,0x20,0x18,0x20,0x7F}, // 87 W
    {0x63,0x14,0x08,0x14,0x63}, // 88 X
    {0x03,0x04,0x78,0x04,0x03}, // 89 Y
    {0x61,0x51,0x49,0x45,0x43}, // 90 Z
    {0x00,0x00,0x7F,0x41,0x41}, // 91 [
    {0x02,0x04,0x08,0x10,0x20}, // 92 backslash
    {0x41,0x41,0x7F,0x00,0x00}, // 93 ]
    {0x04,0x02,0x01,0x02,0x04}, // 94 ^
    {0x40,0x40,0x40,0x40,0x40}, // 95 _
    {0x00,0x01,0x02,0x04,0x00}, // 96 `
    {0x20,0x54,0x54,0x54,0x78}, // 97 a
    {0x7F,0x48,0x44,0x44,0x38}, // 98 b
    {0x38,0x44,0x44,0x44,0x20}, // 99 c
    {0x38,0x44,0x44,0x48,0x7F}, // 100 d
    {0x38,0x54,0x54,0x54,0x18}, // 101 e
    {0x08,0x7E,0x09,0x01,0x02}, // 102 f
    {0x08,0x14,0x54,0x54,0x3C}, // 103 g
    {0x7F,0x08,0x04,0x04,0x78}, // 104 h
    {0x00,0x44,0x7D,0x40,0x00}, // 105 i
    {0x20,0x40,0x44,0x3D,0x00}, // 106 j
    {0x00,0x7F,0x10,0x28,0x44}, // 107 k
    {0x00,0x41,0x7F,0x40,0x00}, // 108 l
    {0x7C,0x04,0x18,0x04,0x78}, // 109 m
    {0x7C,0x08,0x04,0x04,0x78}, // 110 n
    {0x38,0x44,0x44,0x44,0x38}, // 111 o
    {0x7C,0x14,0x14,0x14,0x08}, // 112 p
    {0x08,0x14,0x14,0x18,0x7C}, // 113 q
    {0x7C,0x08,0x04,0x04,0x08}, // 114 r
    {0x48,0x54,0x54,0x54,0x20}, // 115 s
    {0x04,0x3F,0x44,0x40,0x20}, // 116 t
    {0x3C,0x40,0x40,0x20,0x7C}, // 117 u
    {0x1C,0x20,0x40,0x20,0x1C}, // 118 v
    {0x3C,0x40,0x30,0x40,0x3C}, // 119 w
    {0x44,0x28,0x10,0x28,0x44}, // 120 x
    {0x0C,0x50,0x50,0x50,0x3C}, // 121 y
    {0x44,0x64,0x54,0x4C,0x44}, // 122 z
    {0x00,0x08,0x36,0x41,0x00}, // 123 {
    {0x00,0x00,0x7F,0x00,0x00}, // 124 |
    {0x00,0x41,0x36,0x08,0x00}, // 125 }
    {0x08,0x04,0x08,0x10,0x08}, // 126 ~
};

#define FONT_W       5
#define FONT_H       8
#define FONT_ADVANCE 6

// -------------------------------------------------------------------------
// Raw ST7789 panel IO
// -------------------------------------------------------------------------

void display_init(void)
{
    if (!s_lock) s_lock = xSemaphoreCreateRecursiveMutex();
    if (!s_lock) return;
    lock_display();
    if (s_initialized) { unlock_display(); return; }

    gpio_config_t pins = {};
    pins.pin_bit_mask = (1ULL << BOARD_VEXT_ENABLE_PIN) |
                        (1ULL << BOARD_OLED_RST_PIN) |
                        (1ULL << BOARD_LORA_RST_PIN) |
                        (1ULL << BOARD_LORA_CS_PIN);
    pins.mode = GPIO_MODE_OUTPUT;
    esp_err_t err = gpio_config(&pins);
    if (err == ESP_OK) {
        gpio_set_level(BOARD_LORA_CS_PIN, 1);
        gpio_set_level(BOARD_LORA_RST_PIN, 0); // SX1262 stays in reset; Find My uses BLE.
        gpio_set_level(BOARD_VEXT_ENABLE_PIN, 0); // Vext active low.
        gpio_set_level(BOARD_OLED_RST_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(20));
        gpio_set_level(BOARD_OLED_RST_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    i2c_master_bus_config_t bus = {};
    bus.i2c_port = I2C_NUM_0;
    bus.sda_io_num = BOARD_I2C_SDA_PIN;
    bus.scl_io_num = BOARD_I2C_SCL_PIN;
    bus.clk_source = I2C_CLK_SRC_DEFAULT;
    bus.glitch_ignore_cnt = 7;
    bus.flags.enable_internal_pullup = true;
    if (err == ESP_OK) err = i2c_new_master_bus(&bus, &s_bus);
    i2c_device_config_t device = {};
    device.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    device.device_address = BOARD_OLED_ADDRESS;
    device.scl_speed_hz = 100000;
    if (err == ESP_OK) err = i2c_master_bus_add_device(s_bus, &device, &s_oled);
    if (err == ESP_OK) err = i2c_master_probe(s_bus, BOARD_OLED_ADDRESS, 100);
    // Page addressing matches the existing monochrome Nucula framebuffer.
    const uint8_t init[] = {
        0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40,
        0x8D, 0x14, 0x20, 0x02, 0xA1, 0xC8, 0xDA, 0x12,
        0x81, 0x7F, 0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6,
    };
    if (err == ESP_OK) {
        for (const auto value : init)
            if (!command(value)) { err = ESP_FAIL; break; }
    }
    if (err == ESP_OK) {
        memset(s_fb, 0, sizeof(s_fb));
        if (!flush_locked() || !command(0xAF)) err = ESP_FAIL;
    }
    s_initialized = err == ESP_OK;
    s_powered = s_initialized;
    unlock_display();
    if (err != ESP_OK)
        ESP_LOGE("display", "Heltec SSD1306 initialization failed: %s", esp_err_to_name(err));
    else
        ESP_LOGI("display", "SSD1306 128x64 @0x3C, SDA17 SCL18 RST21 Vext36");

    // Keep the physical sender control available even if the OLED fails.
    err = board_tdisplay_buttons_init();
    if (err != ESP_OK) ESP_LOGE("display", "button init: %s", esp_err_to_name(err));
}
void display_update(void)
{
    lock_display();
    if (s_initialized && s_powered && !flush_locked())
        ESP_LOGW("display", "OLED transfer failed; retrying on next refresh");
    unlock_display();
}
void display_clear(void)
{
    lock_display();
    memset(s_fb, 0, sizeof(s_fb));
    unlock_display();
}
void display_power(bool on)
{
    lock_display(); power_locked(on); unlock_display();
}
bool display_is_powered(void)
{
    lock_display();
    const bool on = s_initialized && s_powered;
    unlock_display();
    return on;
}
void display_toggle(void)
{
    lock_display(); power_locked(!s_powered); unlock_display();
}

void display_pixel(int x, int y, bool on)
{
    lock_display();
    pixel_locked(x, y, on);
    unlock_display();
}

void display_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    lock_display();
    int x2 = x + w, y2 = y + h;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x2 > LCD_W) x2 = LCD_W;
    if (y2 > LCD_H) y2 = LCD_H;
    if (x2 <= x || y2 <= y) {
        unlock_display();
        return;
    }

    bool on = (color != 0);
    for (int row = y; row < y2; row++) {
        uint8_t mask = 1 << (row & 7);
        int page_off = (row >> 3) * LCD_W;
        if (on) {
            for (int col = x; col < x2; col++)
                s_fb[page_off + col] |= mask;
        } else {
            uint8_t nmask = ~mask;
            for (int col = x; col < x2; col++)
                s_fb[page_off + col] &= nmask;
        }
    }
    unlock_display();
}

void display_hline(int x, int y, int w)
{
    display_fill_rect(x, y, w, 1, COLOR_WHITE);
}

// -------------------------------------------------------------------------
// Text rendering
// -------------------------------------------------------------------------

void display_text_color(int x, int y, const char *text,
                        uint16_t fg, uint16_t bg, int scale)
{
    if (!text || !*text || scale <= 0)
        return;
    lock_display();
    bool fg_on = (fg != 0);
    bool bg_on = (bg != 0);

    for (; *text; text++, x += FONT_ADVANCE * scale) {
        if (x + FONT_ADVANCE * scale > LCD_W) break;

        char ch = *text;
        if (ch < 32 || ch > 126) ch = '?';
        const uint8_t *glyph = font5x7[ch - 32];

        for (int row = 0; row < FONT_H; row++) {
            int py = y + row * scale;
            if (py >= LCD_H) break;
            for (int col = 0; col < FONT_ADVANCE; col++) {
                bool on = (col < FONT_W) && (glyph[col] & (1 << row));
                bool pixel = on ? fg_on : bg_on;
                int px = x + col * scale;
                for (int sy = 0; sy < scale && py + sy < LCD_H; sy++)
                    for (int sx = 0; sx < scale && px + sx < LCD_W; sx++)
                        pixel_locked(px + sx, py + sy, pixel);
            }
        }
    }
    unlock_display();
}

void display_text(int x, int y, const char *text, int scale)
{
    display_text_color(x, y, text, COLOR_WHITE, COLOR_BLACK, scale);
}

void display_text_inv(int x, int y, const char *text, int scale)
{
    display_text_color(x, y, text, COLOR_BLACK, COLOR_WHITE, scale);
}

int display_text_width(const char *text, int scale)
{
    if (!text || scale <= 0)
        return 0;
    return static_cast<int>(strlen(text)) * FONT_ADVANCE * scale;
}

