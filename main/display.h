#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "board.h"

#ifdef __cplusplus
extern "C" {
#endif

// Selected board's native landscape display dimensions.
#define LCD_W BOARD_TFT_WIDTH
#define LCD_H BOARD_TFT_HEIGHT

// One-bit UI framebuffer. ST7789 expands it to RGB565 when flushing; SSD1306
// sends its native monochrome pages.
#define COLOR_BLACK  0x0000
#define COLOR_WHITE  0x0001
#define COLOR_GREEN  0x0001
#define COLOR_CYAN   0x0001
#define COLOR_AMBER  0x0001
#define COLOR_DGRAY  0x0001
#define COLOR_LGRAY  0x0001

// Each backend owns its display bus (T-Display SPI / Heltec OLED I2C).
void display_init(void);

void display_clear(void);
void display_update(void);

void display_fill_rect(int x, int y, int w, int h, uint16_t color);

void display_text(int x, int y, const char *text, int scale);
void display_text_inv(int x, int y, const char *text, int scale);
void display_text_color(int x, int y, const char *text,
                        uint16_t fg, uint16_t bg, int scale);

int display_text_width(const char *text, int scale);

void display_hline(int x, int y, int w);
void display_pixel(int x, int y, bool on);

// Put both the LCD controller and its backlight into/out of their low-power
// state. Drawing while powered down updates RAM; the newest frame is flushed
// before the backlight is restored.
void display_power(bool on);
bool display_is_powered(void);
void display_toggle(void);

#ifdef __cplusplus
}
#endif
