#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*board_tdisplay_dispersion_handler_t)(void *context);

typedef enum {
    BOARD_TDISPLAY_POWER_UNKNOWN = 0,
    BOARD_TDISPLAY_POWER_BATTERY,
    BOARD_TDISPLAY_POWER_USB,
} board_tdisplay_power_source_t;

typedef struct {
    board_tdisplay_power_source_t source;
    uint16_t millivolts;
    uint8_t percent;
    bool calibrated;
    bool sense_enabled_high;
} board_tdisplay_power_status_t;

// Board power/buttons API (legacy name retained for the T-Display backend).
// T-Display: gated 2:1 input-rail divider. Heltec: gated 4.9:1 VBAT divider.
// Uses the chip's ADC calibration scheme when available.
esp_err_t board_tdisplay_power_init(void);

// Sample the rail. Heltec reads battery voltage only, with no charge-status
// detection. T-Display readings above the LiPo range are reported as USB.
// The divider is enabled only for the duration of this call.
esp_err_t board_tdisplay_power_read(board_tdisplay_power_status_t *status);

// T-Display: GPIO0 screen / GPIO35 sender. Heltec: GPIO0 short press screen,
// >=1-second hold then release sender. Held-at-boot buttons are suppressed.
// Safe to call more than once.
esp_err_t board_tdisplay_buttons_init(void);

// Register the application-owned action for the selected sender button. The display initializes
// the buttons early during boot, so a null handler intentionally leaves the
// dispersion button inert until the durable outbox is ready.
void board_tdisplay_set_dispersion_handler(
    board_tdisplay_dispersion_handler_t handler, void *context);

#ifdef __cplusplus
}
#endif
