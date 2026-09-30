#pragma once

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_CONNECTED_BIT BIT0

/**
 * Initialize WiFi in station mode and start the supervisor task.
 *
 * Spawns a long-lived FreeRTOS task that, while disconnected, periodically
 * re-tries esp_wifi_connect(). The initial connect attempt blocks for up to
 * 15 seconds; if it does not succeed in that window the function returns
 * ESP_FAIL while the supervisor keeps trying in the background.
 *
 * Safe to call only once.
 *
 * @return ESP_OK if connected within 15 s, ESP_FAIL otherwise
 */
esp_err_t wifi_init(void);

/**
 * Returns true if WiFi is connected and the device has an IP address.
 */
bool wifi_is_connected(void);

/**
 * Toggle radio power save. Default is WIFI_PS_MIN_MODEM (doze between DTIM
 * beacons, ~100-300 ms first-packet latency). Pass true to disable power
 * save for a latency-critical window (an active NFC payment), false to
 * restore it.
 */
void wifi_set_low_latency(bool on);

/**
 * Protect an active Find My backlog from Wi-Fi state churn. While active,
 * existing Wi-Fi connectivity is left untouched, new reconnect scans are
 * deferred, and ESP32 coexistence gives Bluetooth more RF opportunities.
 * Releasing the guard restores balanced coexistence and wakes the reconnect
 * supervisor immediately if the link is down.
 */
void wifi_set_find_my_radio_guard(bool active);

/**
 * Returns the FreeRTOS event group whose WIFI_CONNECTED_BIT is set whenever
 * the device is associated and has an IP, and cleared on disconnect. Other
 * tasks can wait on this bit to react to (re)connection events.
 */
EventGroupHandle_t wifi_get_event_group(void);

#ifdef __cplusplus
}
#endif
