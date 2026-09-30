#include "display.h"

#include <cstring>

#include <driver/gpio.h>
#include <driver/spi_master.h>
#include <esp_heap_caps.h>
#include <esp_lcd_io_spi.h>
#include <esp_lcd_panel_io.h>
#include <esp_log.h>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include "board.h"
#include "board_tdisplay.h"

#define TAG "display"

namespace {

// The verified Arduino setup used the default VSPI peripheral at 40 MHz.
constexpr spi_host_device_t kLcdHost = SPI3_HOST;
constexpr int kStripeHeight = 16;
constexpr int kXOffset = BOARD_TFT_X_OFFSET;
constexpr int kYOffset = BOARD_TFT_Y_OFFSET;
constexpr size_t kStripeBytes = LCD_W * kStripeHeight * sizeof(uint16_t);
constexpr TickType_t kTransferTimeout = pdMS_TO_TICKS(250);

esp_lcd_panel_io_handle_t s_io;
SemaphoreHandle_t s_lock;
SemaphoreHandle_t s_tx_done;
uint16_t *s_stripe;
bool s_initialized;
bool s_powered;
bool s_first_frame_sent;

// Page-format one-bit framebuffer. The last page has one unused bit because
// the panel height is 135 pixels.
// Each byte holds 8 vertical pixels; bit 0 = topmost in the page.
uint8_t s_fb[((LCD_H + 7) / 8) * LCD_W];

void lock_display()
{
    if (s_lock)
        xSemaphoreTakeRecursive(s_lock, portMAX_DELAY);
}

void unlock_display()
{
    if (s_lock)
        xSemaphoreGiveRecursive(s_lock);
}

void pixel_locked(int x, int y, bool on)
{
    if (x < 0 || x >= LCD_W || y < 0 || y >= LCD_H)
        return;
    if (on)
        s_fb[(y >> 3) * LCD_W + x] |= (1U << (y & 7));
    else
        s_fb[(y >> 3) * LCD_W + x] &= ~(1U << (y & 7));
}

bool IRAM_ATTR color_transfer_done(esp_lcd_panel_io_handle_t,
                                   esp_lcd_panel_io_event_data_t *, void *)
{
    BaseType_t task_woken = pdFALSE;
    xSemaphoreGiveFromISR(s_tx_done, &task_woken);
    if (task_woken == pdTRUE)
        portYIELD_FROM_ISR(task_woken);
    return task_woken == pdTRUE;
}

bool send_command(uint8_t command, const uint8_t *data = nullptr,
                  size_t data_length = 0)
{
    const esp_err_t err = esp_lcd_panel_io_tx_param(
        s_io, command, data, data_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ST7789 command 0x%02x failed: %s", command,
                 esp_err_to_name(err));
        return false;
    }
    return true;
}

void delay_ms(uint32_t delay)
{
    const TickType_t ticks = pdMS_TO_TICKS(delay);
    vTaskDelay(ticks > 0 ? ticks : 1);
}

} // namespace

// -------------------------------------------------------------------------
// 5×7 bitmap font (ASCII 32-126, 5 bytes per char, column-major, LSB=top)
// -------------------------------------------------------------------------
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

namespace {

bool initialize_controller()
{
    // Match TFT_eSPI 2.2.20's verified hardware-reset timing exactly.
    gpio_set_level(BOARD_TFT_RST_PIN, 1);
    esp_rom_delay_us(5000);
    gpio_set_level(BOARD_TFT_RST_PIN, 0);
    delay_ms(20);
    gpio_set_level(BOARD_TFT_RST_PIN, 1);
    delay_ms(150);

    // Exact command/data sequence from TFT_eSPI 2.2.20 ST7789_Init.h, the
    // revision that was physically verified on this specific T-Display.
    static const uint8_t madctl_bgr[] = {0x08};
    static const uint8_t display_function[] = {0x0A, 0x82};
    static const uint8_t color_mode[] = {0x55};
    static const uint8_t porch[] = {0x0C, 0x0C, 0x00, 0x33, 0x33};
    static const uint8_t gate[] = {0x35};
    static const uint8_t vcom[] = {0x28};
    static const uint8_t lcm[] = {0x0C};
    static const uint8_t vdv_vrh_enable[] = {0x01, 0xFF};
    static const uint8_t vrh[] = {0x10};
    static const uint8_t vdv[] = {0x20};
    static const uint8_t frame_rate[] = {0x0F};
    static const uint8_t power[] = {0xA4, 0xA1};
    static const uint8_t positive_gamma[] = {
        0xD0, 0x00, 0x02, 0x07, 0x0A, 0x28, 0x32,
        0x44, 0x42, 0x06, 0x0E, 0x12, 0x14, 0x17,
    };
    static const uint8_t negative_gamma[] = {
        0xD0, 0x00, 0x02, 0x07, 0x0A, 0x28, 0x31,
        0x54, 0x47, 0x0E, 0x1C, 0x17, 0x1B, 0x1E,
    };
    static const uint8_t initial_columns[] = {0x00, 0x00, 0x00, 0xE5};
    static const uint8_t initial_rows[] = {0x00, 0x00, 0x01, 0x3F};

    if (!send_command(0x11)) // SLPOUT
        return false;
    delay_ms(120);

    if (!send_command(0x13) || // NORON
        !send_command(0x36, madctl_bgr, sizeof(madctl_bgr)) ||
        !send_command(0xB6, display_function, sizeof(display_function)) ||
        !send_command(0x3A, color_mode, sizeof(color_mode)))
        return false;
    delay_ms(10);

    if (!send_command(0xB2, porch, sizeof(porch)) ||
        !send_command(0xB7, gate, sizeof(gate)) ||
        !send_command(0xBB, vcom, sizeof(vcom)) ||
        !send_command(0xC0, lcm, sizeof(lcm)) ||
        !send_command(0xC2, vdv_vrh_enable, sizeof(vdv_vrh_enable)) ||
        !send_command(0xC3, vrh, sizeof(vrh)) ||
        !send_command(0xC4, vdv, sizeof(vdv)) ||
        !send_command(0xC6, frame_rate, sizeof(frame_rate)) ||
        !send_command(0xD0, power, sizeof(power)) ||
        !send_command(0xE0, positive_gamma, sizeof(positive_gamma)) ||
        !send_command(0xE1, negative_gamma, sizeof(negative_gamma)) ||
        !send_command(0x21) || // INVON
        !send_command(0x2A, initial_columns, sizeof(initial_columns)) ||
        !send_command(0x2B, initial_rows, sizeof(initial_rows)))
        return false;

    // The historical driver released CS for this delay before DISPON.
    delay_ms(120);
    if (!send_command(0x29)) // DISPON
        return false;
    delay_ms(120);

    // TFT_eSPI init() applies rotation 0 once, then the known-good app calls
    // setRotation(1). Preserve both writes and the final landscape MADCTL:
    // MX | MV | BGR = 0x68. Rotation 1 uses x=40/y=53 CGRAM offsets.
    if (!send_command(0x36, madctl_bgr, sizeof(madctl_bgr)))
        return false;
    esp_rom_delay_us(10);
    static const uint8_t rotation_1[] = {0x68};
    if (!send_command(0x36, rotation_1, sizeof(rotation_1)))
        return false;
    esp_rom_delay_us(10);
    return true;
}

bool flush_frame_locked()
{
    if (!s_initialized || !s_powered)
        return false;

    for (int y = 0; y < LCD_H; y += kStripeHeight) {
        const int rows = (y + kStripeHeight <= LCD_H)
                             ? kStripeHeight
                             : LCD_H - y;
        size_t out = 0;
        for (int row = 0; row < rows; ++row) {
            const int source_y = y + row;
            const uint8_t mask = 1U << (source_y & 7);
            const int page = (source_y >> 3) * LCD_W;
            for (int x = 0; x < LCD_W; ++x)
                s_stripe[out++] = (s_fb[page + x] & mask) ? 0xFFFF : 0x0000;
        }

        const uint16_t x0 = kXOffset;
        const uint16_t x1 = kXOffset + LCD_W - 1;
        const uint16_t y0 = kYOffset + y;
        const uint16_t y1 = kYOffset + y + rows - 1;
        const uint8_t columns[] = {
            static_cast<uint8_t>(x0 >> 8), static_cast<uint8_t>(x0),
            static_cast<uint8_t>(x1 >> 8), static_cast<uint8_t>(x1),
        };
        const uint8_t rows_window[] = {
            static_cast<uint8_t>(y0 >> 8), static_cast<uint8_t>(y0),
            static_cast<uint8_t>(y1 >> 8), static_cast<uint8_t>(y1),
        };

        if (!send_command(0x2A, columns, sizeof(columns)) ||
            !send_command(0x2B, rows_window, sizeof(rows_window)))
            return false;

        // Defensive drain in case a previous transfer completed after a
        // timeout. With queue depth one, this stripe stays valid until the
        // callback returns its completion token.
        while (xSemaphoreTake(s_tx_done, 0) == pdTRUE) {
        }
        const esp_err_t err = esp_lcd_panel_io_tx_color(
            s_io, 0x2C, s_stripe, out * sizeof(uint16_t));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "ST7789 stripe transfer failed: %s",
                     esp_err_to_name(err));
            return false;
        }
        if (xSemaphoreTake(s_tx_done,
                           kTransferTimeout > 0 ? kTransferTimeout : 1) != pdTRUE) {
            ESP_LOGE(TAG, "ST7789 stripe transfer timed out");
            return false;
        }
    }

    // Never expose reset/uninitialised panel RAM. The backlight comes on only
    // after a complete first frame (also after waking from sleep).
    if (!s_first_frame_sent) {
        gpio_set_level(BOARD_TFT_BACKLIGHT_PIN, 1);
        s_first_frame_sent = true;
    }
    return true;
}

void set_power_locked(bool on)
{
    if (!s_initialized || on == s_powered)
        return;

    if (!on) {
        gpio_set_level(BOARD_TFT_BACKLIGHT_PIN, 0);
        send_command(0x28); // DISPOFF
        delay_ms(20);
        send_command(0x10); // SLPIN
        delay_ms(120);
        s_powered = false;
        s_first_frame_sent = false;
        return;
    }

    if (!send_command(0x11)) // SLPOUT
        return;
    delay_ms(120);
    if (!send_command(0x29)) // DISPON
        return;
    delay_ms(120);
    s_powered = true;
    s_first_frame_sent = false;
    flush_frame_locked();
}

} // namespace

// -------------------------------------------------------------------------
// Init and framebuffer transfer
// -------------------------------------------------------------------------

void display_init(void)
{
    if (!s_lock)
        s_lock = xSemaphoreCreateRecursiveMutex();
    if (!s_lock) {
        ESP_LOGE(TAG, "display mutex allocation failed");
        return;
    }

    lock_display();
    if (s_initialized) {
        unlock_display();
        return;
    }

    gpio_config_t output_cfg = {};
    output_cfg.pin_bit_mask = (1ULL << BOARD_TFT_RST_PIN) |
                              (1ULL << BOARD_TFT_BACKLIGHT_PIN);
    output_cfg.mode = GPIO_MODE_OUTPUT;
    output_cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    output_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    output_cfg.intr_type = GPIO_INTR_DISABLE;
    esp_err_t err = gpio_config(&output_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "display GPIO init failed: %s", esp_err_to_name(err));
        unlock_display();
        return;
    }
    gpio_set_level(BOARD_TFT_BACKLIGHT_PIN, 0);
    gpio_set_level(BOARD_TFT_RST_PIN, 1);

    if (!s_tx_done)
        s_tx_done = xSemaphoreCreateBinary();
    if (!s_stripe)
        s_stripe = static_cast<uint16_t *>(
            heap_caps_malloc(kStripeBytes, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
    if (!s_tx_done || !s_stripe) {
        ESP_LOGE(TAG, "DMA stripe/semaphore allocation failed");
        unlock_display();
        return;
    }

    spi_bus_config_t bus_config = {};
    bus_config.mosi_io_num = BOARD_TFT_MOSI_PIN;
    bus_config.miso_io_num = -1;
    bus_config.sclk_io_num = BOARD_TFT_SCLK_PIN;
    bus_config.quadwp_io_num = -1;
    bus_config.quadhd_io_num = -1;
    bus_config.data4_io_num = -1;
    bus_config.data5_io_num = -1;
    bus_config.data6_io_num = -1;
    bus_config.data7_io_num = -1;
    bus_config.max_transfer_sz = kStripeBytes;
    bus_config.flags = SPICOMMON_BUSFLAG_MASTER |
                       SPICOMMON_BUSFLAG_MOSI |
                       SPICOMMON_BUSFLAG_SCLK;

    err = spi_bus_initialize(kLcdHost, &bus_config, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "display SPI bus init failed: %s", esp_err_to_name(err));
        unlock_display();
        return;
    }

    esp_lcd_panel_io_spi_config_t io_config = {};
    io_config.cs_gpio_num = BOARD_TFT_CS_PIN;
    io_config.dc_gpio_num = BOARD_TFT_DC_PIN;
    io_config.spi_mode = 0;
    io_config.pclk_hz = BOARD_TFT_CLOCK_HZ;
    io_config.trans_queue_depth = 1;
    io_config.on_color_trans_done = color_transfer_done;
    io_config.user_ctx = nullptr;
    io_config.lcd_cmd_bits = 8;
    io_config.lcd_param_bits = 8;

    err = esp_lcd_new_panel_io_spi(
        static_cast<esp_lcd_spi_bus_handle_t>(kLcdHost), &io_config, &s_io);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "display panel IO init failed: %s", esp_err_to_name(err));
        unlock_display();
        return;
    }

    if (!initialize_controller()) {
        ESP_LOGE(TAG, "ST7789 initialization failed");
        unlock_display();
        return;
    }

    memset(s_fb, 0, sizeof(s_fb));
    s_initialized = true;
    s_powered = true;
    s_first_frame_sent = false;
    const bool first_frame_ok = flush_frame_locked();
    unlock_display();

    if (!first_frame_ok) {
        ESP_LOGE(TAG, "ST7789 first frame failed; backlight remains off");
        return;
    }

    err = board_tdisplay_buttons_init();
    if (err != ESP_OK)
        ESP_LOGE(TAG, "display button init failed: %s", esp_err_to_name(err));

    ESP_LOGI(TAG,
             "ST7789 initialized (%dx%d rotation 1, offset %d/%d, 40 MHz)",
             LCD_W, LCD_H, kXOffset, kYOffset);
}

void display_update(void)
{
    lock_display();
    if (s_initialized && s_powered)
        flush_frame_locked();
    unlock_display();
}

void display_power(bool on)
{
    lock_display();
    set_power_locked(on);
    unlock_display();
}

bool display_is_powered(void)
{
    lock_display();
    const bool powered = s_initialized && s_powered;
    unlock_display();
    return powered;
}

void display_toggle(void)
{
    lock_display();
    set_power_locked(!s_powered);
    unlock_display();
}

void display_clear(void)
{
    lock_display();
    memset(s_fb, 0, sizeof(s_fb));
    unlock_display();
}

// -------------------------------------------------------------------------
// Drawing primitives
// -------------------------------------------------------------------------

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
