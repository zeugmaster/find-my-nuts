#pragma once

#include "driver/gpio.h"
#include "sdkconfig.h"

#if CONFIG_BOARD_HELTEC_V3

// Heltec WiFi LoRa 32 V3 / V3.1 / V3.2, ESP32-S3FN8, 8 MiB flash.
// Sources and schematic links: docs/HELTEC_V3.md.
#define BOARD_NAME                   "Heltec WiFi LoRa 32 V3"
#define BOARD_TFT_WIDTH              128
#define BOARD_TFT_HEIGHT             64
#define BOARD_I2C_SDA_PIN            GPIO_NUM_17
#define BOARD_I2C_SCL_PIN            GPIO_NUM_18
#define BOARD_OLED_RST_PIN           GPIO_NUM_21
#define BOARD_VEXT_ENABLE_PIN        GPIO_NUM_36
#define BOARD_OLED_ADDRESS           0x3C
#define BOARD_DISPERSION_BUTTON_PIN  GPIO_NUM_0
#define BOARD_BUTTON_HINT            "hold PRG 1s, release"
#define BOARD_BATTERY_ADC_PIN        GPIO_NUM_1
#define BOARD_BATTERY_ADC_ENABLE_PIN GPIO_NUM_37
#define BOARD_UART_TX_PIN            GPIO_NUM_43
#define BOARD_UART_RX_PIN            GPIO_NUM_44
#define BOARD_UART_BAUD_RATE         115200
#define BOARD_LORA_RST_PIN           GPIO_NUM_12
#define BOARD_LORA_CS_PIN            GPIO_NUM_8

#else

#define BOARD_NAME                   "TTGO T-Display"
#define BOARD_BUTTON_HINT            "press GPIO35"

// Board definition: original LILYGO/TTGO T-Display (classic ESP32).
//
// This is the 1.14-inch, 135x240 ST7789 board, not the T-Display-S3.
// The display is used in rotation 1 (240x135 landscape).  Keep this pin map
// here so the wallet, display and button code do not grow board-specific
// literals independently.

// ST7789 write-only SPI bus
#define BOARD_TFT_MOSI_PIN       GPIO_NUM_19
#define BOARD_TFT_SCLK_PIN       GPIO_NUM_18
#define BOARD_TFT_CS_PIN         GPIO_NUM_5
#define BOARD_TFT_DC_PIN         GPIO_NUM_16
#define BOARD_TFT_RST_PIN        GPIO_NUM_23
#define BOARD_TFT_BACKLIGHT_PIN  GPIO_NUM_4
#define BOARD_TFT_WIDTH           240
#define BOARD_TFT_HEIGHT          135
#define BOARD_TFT_X_OFFSET        40
#define BOARD_TFT_Y_OFFSET        53
#define BOARD_TFT_CLOCK_HZ        40000000

// The two active-low board buttons have separate roles. GPIO35 is input-only,
// externally pulled up, and is the safe physical-only dispersion control.
// GPIO0 is connected to the board's boot/USB auto-reset network, so it is used
// only for the non-sensitive display toggle; it must never be driven by
// firmware or held while the board is reset.
#define BOARD_DISPLAY_BUTTON_PIN    GPIO_NUM_0
#define BOARD_DISPERSION_BUTTON_PIN GPIO_NUM_35

// The original T-Display routes its input rail through a nominal 2:1 divider
// to ADC1 GPIO34. GPIO14 enables the divider; keep it low between samples to
// avoid the divider's continuous battery drain.
#define BOARD_BATTERY_ADC_PIN       GPIO_NUM_34
#define BOARD_BATTERY_ADC_ENABLE_PIN GPIO_NUM_14

// UART0 is connected to the on-board WCH CH9102 USB/UART bridge.
#define BOARD_UART_TX_PIN        GPIO_NUM_1
#define BOARD_UART_RX_PIN        GPIO_NUM_3
#define BOARD_UART_BAUD_RATE     115200

// Legacy pin definitions retained for the unbuilt optional I2C/keypad sources.
// This T-Display target does not initialize or probe an I2C bus.
#define BOARD_I2C_SDA_PIN        GPIO_NUM_21
#define BOARD_I2C_SCL_PIN        GPIO_NUM_22
#define BOARD_KEYPAD_ADDR        0x20

#endif
