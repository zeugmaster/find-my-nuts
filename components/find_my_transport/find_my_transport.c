/*
 * Find My byte transport for the ESP32, derived from
 * positive-security/send-my and OpenHaystack via esp-find-my.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "find_my_transport.h"
#include "find_my_schedule.h"

#include <inttypes.h>
#include <limits.h>
#include <string.h>

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "uECC.h"

#if !CONFIG_BT_ENABLED || !CONFIG_BT_BLUEDROID_ENABLED
#error "find_my_transport requires CONFIG_BT_ENABLED and Bluedroid"
#endif

#define FIND_MY_GAP_TIMEOUT_MS 5000U
#define FIND_MY_ADV_INTERVAL_UNITS \
    ((CONFIG_FIND_MY_TRANSPORT_ADV_INTERVAL_MS * 8U + 2U) / 5U)

#define FIND_MY_EVENT_ADDRESS_SET BIT0
#define FIND_MY_EVENT_ADV_CONFIGURED BIT1
#define FIND_MY_EVENT_ADV_STARTED BIT2
#define FIND_MY_EVENT_ADV_STOPPED BIT3
#define FIND_MY_EVENT_GAP_ERROR BIT4
#define FIND_MY_EVENT_CANCEL BIT5
#define FIND_MY_EVENT_SEND_DONE BIT6
#define FIND_MY_EVENT_GAP_ALL \
    (FIND_MY_EVENT_ADDRESS_SET | FIND_MY_EVENT_ADV_CONFIGURED | \
     FIND_MY_EVENT_ADV_STARTED | FIND_MY_EVENT_ADV_STOPPED | \
     FIND_MY_EVENT_GAP_ERROR)

_Static_assert(FIND_MY_ADV_INTERVAL_UNITS >= 0x20U, "BLE interval is too short");
_Static_assert(FIND_MY_ADV_INTERVAL_UNITS <= 0x4000U, "BLE interval is too long");

typedef enum {
    FIND_MY_INIT_NOT_STARTED = 0,
    FIND_MY_INIT_IN_PROGRESS,
    FIND_MY_INIT_FINISHED,
} find_my_init_state_t;

static const char *const TAG = "find_my_transport";

static portMUX_TYPE s_state_lock = portMUX_INITIALIZER_UNLOCKED;
static volatile find_my_init_state_t s_init_state = FIND_MY_INIT_NOT_STARTED;
static esp_err_t s_init_result = ESP_ERR_INVALID_STATE;
static EventGroupHandle_t s_events;
static SemaphoreHandle_t s_send_mutex;
static TaskHandle_t s_send_task;
static volatile bool s_advertising_active;

static find_my_transport_progress_t s_progress = {
    .status = FIND_MY_TRANSPORT_UNINITIALIZED,
    .current_symbol_index = UINT32_MAX,
    .last_result = ESP_ERR_INVALID_STATE,
};

/** Random-static BLE address derived from the active Find My public key. */
static esp_bd_addr_t s_random_address = {0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/** Apple Offline Finding manufacturer advertisement. */
static uint8_t s_adv_data[31] = {
    0x1e,       /* Length (30). */
    0xff,       /* Manufacturer Specific Data. */
    0x4c, 0x00, /* Apple company ID. */
    0x12, 0x19, /* Offline Finding type and length. */
    0x00,       /* State. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* First two public-key bits. */
    0x00, /* Hint. */
};

static esp_ble_adv_params_t s_adv_params = {
    .adv_int_min = FIND_MY_ADV_INTERVAL_UNITS,
    .adv_int_max = FIND_MY_ADV_INTERVAL_UNITS,
    .adv_type = ADV_TYPE_NONCONN_IND,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void copy_u32_be(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value >> 24);
    destination[1] = (uint8_t)(value >> 16);
    destination[2] = (uint8_t)(value >> 8);
    destination[3] = (uint8_t)value;
}

static void copy_progress(find_my_transport_progress_t *destination)
{
    taskENTER_CRITICAL(&s_state_lock);
    *destination = s_progress;
    destination->advertising = s_advertising_active;
    taskEXIT_CRITICAL(&s_state_lock);
}

static void notify_progress(find_my_progress_cb_t callback, void *context)
{
    if (callback == NULL) {
        return;
    }

    find_my_transport_progress_t snapshot;
    copy_progress(&snapshot);
    callback(&snapshot, context);
}

static void set_gap_error(const char *operation, esp_bt_status_t status)
{
    ESP_LOGE(TAG, "%s failed with Bluetooth status %d", operation, (int)status);
    if (s_events != NULL) {
        xEventGroupSetBits(s_events, FIND_MY_EVENT_GAP_ERROR);
    }
}

static void gap_callback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *parameter)
{
    switch (event) {
    case ESP_GAP_BLE_SET_STATIC_RAND_ADDR_EVT:
        if (parameter->set_rand_addr_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            xEventGroupSetBits(s_events, FIND_MY_EVENT_ADDRESS_SET);
        } else {
            set_gap_error("setting random address", parameter->set_rand_addr_cmpl.status);
        }
        break;

    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        if (parameter->adv_data_raw_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            xEventGroupSetBits(s_events, FIND_MY_EVENT_ADV_CONFIGURED);
        } else {
            set_gap_error("configuring advertisement", parameter->adv_data_raw_cmpl.status);
        }
        break;

    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        if (parameter->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            taskENTER_CRITICAL(&s_state_lock);
            s_advertising_active = true;
            taskEXIT_CRITICAL(&s_state_lock);
            xEventGroupSetBits(s_events, FIND_MY_EVENT_ADV_STARTED);
        } else {
            set_gap_error("starting advertisement", parameter->adv_start_cmpl.status);
        }
        break;

    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        if (parameter->adv_stop_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            taskENTER_CRITICAL(&s_state_lock);
            s_advertising_active = false;
            taskEXIT_CRITICAL(&s_state_lock);
            xEventGroupSetBits(s_events, FIND_MY_EVENT_ADV_STOPPED);
        } else {
            set_gap_error("stopping advertisement", parameter->adv_stop_cmpl.status);
        }
        break;

    default:
        break;
    }
}

static esp_err_t wait_for_gap_event(EventBits_t expected)
{
    EventBits_t bits = xEventGroupWaitBits(
        s_events,
        expected | FIND_MY_EVENT_GAP_ERROR,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(FIND_MY_GAP_TIMEOUT_MS));

    if ((bits & FIND_MY_EVENT_GAP_ERROR) != 0U) {
        return ESP_FAIL;
    }
    if ((bits & expected) == 0U) {
        ESP_LOGE(TAG, "timed out waiting for GAP event 0x%" PRIx32, (uint32_t)expected);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

static void clear_gap_events(void)
{
    xEventGroupClearBits(s_events, FIND_MY_EVENT_GAP_ALL);
}

static bool public_key_x_is_valid(const uint8_t public_key_x[28])
{
    uint8_t compressed[29];
    uint8_t uncompressed[56];
    const struct uECC_Curve_t *curve = uECC_secp224r1();

    compressed[0] = 0x02;
    memcpy(&compressed[1], public_key_x, 28);
    uECC_decompress(compressed, uncompressed, curve);
    return uECC_valid_public_key(uncompressed, curve) != 0;
}

static void set_address_and_payload_from_key(const uint8_t public_key_x[28])
{
    s_random_address[0] = public_key_x[0] | 0xC0U;
    memcpy(&s_random_address[1], &public_key_x[1], 5);
    memcpy(&s_adv_data[7], &public_key_x[6], 22);
    s_adv_data[29] = public_key_x[0] >> 6;
}

/*
 * Public-key x-coordinate wire layout (28 bytes):
 * [BA BE] [symbol index u32 BE] [message ID u32 BE] [modem ID u32 BE]
 * [valid-key counter u32 BE] [9 zero bytes] [2-bit symbol value]
 */
static esp_err_t prepare_symbol(uint32_t symbol_index, uint32_t message_id, uint8_t symbol)
{
    uint8_t public_key_x[28] = {0};
    public_key_x[0] = 0xBA;
    public_key_x[1] = 0xBE;
    copy_u32_be(&public_key_x[2], symbol_index);
    copy_u32_be(&public_key_x[6], message_id);
    copy_u32_be(&public_key_x[10], CONFIG_FIND_MY_TRANSPORT_MODEM_ID);
    public_key_x[27] = symbol;

    uint32_t counter = 0;
    while (true) {
        copy_u32_be(&public_key_x[14], counter);
        if (public_key_x_is_valid(public_key_x)) {
            ESP_LOGD(TAG, "symbol %" PRIu32 " key valid at counter %" PRIu32,
                     symbol_index, counter);
            set_address_and_payload_from_key(public_key_x);
            return ESP_OK;
        }
        if (counter == UINT32_MAX) {
            return ESP_ERR_NOT_FOUND;
        }
        counter++;
    }
}

static esp_err_t stop_advertising_from_sender(void)
{
    bool active;
    taskENTER_CRITICAL(&s_state_lock);
    active = s_advertising_active;
    taskEXIT_CRITICAL(&s_state_lock);
    if (!active) {
        return ESP_OK;
    }

    clear_gap_events();
    esp_err_t error = esp_ble_gap_stop_advertising();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "request to stop advertising failed: %s", esp_err_to_name(error));
        return error;
    }
    return wait_for_gap_event(FIND_MY_EVENT_ADV_STOPPED);
}

static esp_err_t advertise_prepared_symbol(void)
{
    esp_err_t error = stop_advertising_from_sender();
    if (error != ESP_OK) {
        return error;
    }

    clear_gap_events();
    error = esp_ble_gap_set_rand_addr(s_random_address);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "request to set random address failed: %s", esp_err_to_name(error));
        return error;
    }
    error = wait_for_gap_event(FIND_MY_EVENT_ADDRESS_SET);
    if (error != ESP_OK) {
        return error;
    }

    clear_gap_events();
    error = esp_ble_gap_config_adv_data_raw(s_adv_data, sizeof(s_adv_data));
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "request to configure advertisement failed: %s", esp_err_to_name(error));
        return error;
    }
    error = wait_for_gap_event(FIND_MY_EVENT_ADV_CONFIGURED);
    if (error != ESP_OK) {
        return error;
    }

    clear_gap_events();
    error = esp_ble_gap_start_advertising(&s_adv_params);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "request to start advertisement failed: %s", esp_err_to_name(error));
        return error;
    }
    error = wait_for_gap_event(FIND_MY_EVENT_ADV_STARTED);
    if (error != ESP_OK) {
        return error;
    }

    EventBits_t bits = xEventGroupWaitBits(
        s_events,
        FIND_MY_EVENT_CANCEL,
        pdFALSE,
        pdFALSE,
        pdMS_TO_TICKS(CONFIG_FIND_MY_TRANSPORT_SYMBOL_DWELL_MS));
    bool cancelled = (bits & FIND_MY_EVENT_CANCEL) != 0U;

    error = stop_advertising_from_sender();
    if (error != ESP_OK) {
        return error;
    }
    return cancelled ? ESP_ERR_INVALID_STATE : ESP_OK;
}

static esp_err_t initialize_bluetooth(void)
{
    esp_bt_controller_status_t controller_status = esp_bt_controller_get_status();
    if (controller_status == ESP_BT_CONTROLLER_STATUS_IDLE) {
        /* A repeat release reports INVALID_STATE; either state is usable here. */
        esp_err_t release_error = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
        if (release_error != ESP_OK && release_error != ESP_ERR_INVALID_STATE) {
            return release_error;
        }

        esp_bt_controller_config_t controller_config = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        esp_err_t error = esp_bt_controller_init(&controller_config);
        if (error != ESP_OK) {
            return error;
        }
        controller_status = ESP_BT_CONTROLLER_STATUS_INITED;
    }

    if (controller_status == ESP_BT_CONTROLLER_STATUS_INITED) {
        esp_err_t error = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        if (error != ESP_OK) {
            return error;
        }
    }

    esp_bluedroid_status_t bluedroid_status = esp_bluedroid_get_status();
    if (bluedroid_status == ESP_BLUEDROID_STATUS_UNINITIALIZED) {
        esp_err_t error = esp_bluedroid_init();
        if (error != ESP_OK) {
            return error;
        }
        bluedroid_status = ESP_BLUEDROID_STATUS_INITIALIZED;
    }
    if (bluedroid_status == ESP_BLUEDROID_STATUS_INITIALIZED) {
        esp_err_t error = esp_bluedroid_enable();
        if (error != ESP_OK) {
            return error;
        }
    }

    return esp_ble_gap_register_callback(gap_callback);
}

esp_err_t find_my_transport_init(void)
{
    bool initialize = false;

    taskENTER_CRITICAL(&s_state_lock);
    if (s_init_state == FIND_MY_INIT_NOT_STARTED) {
        s_init_state = FIND_MY_INIT_IN_PROGRESS;
        initialize = true;
    }
    taskEXIT_CRITICAL(&s_state_lock);

    if (!initialize) {
        while (s_init_state == FIND_MY_INIT_IN_PROGRESS) {
            vTaskDelay(1);
        }
        return s_init_result;
    }

    s_events = xEventGroupCreate();
    s_send_mutex = xSemaphoreCreateMutex();
    esp_err_t result = (s_events != NULL && s_send_mutex != NULL) ? ESP_OK : ESP_ERR_NO_MEM;
    if (result == ESP_OK) {
        result = initialize_bluetooth();
    }

    taskENTER_CRITICAL(&s_state_lock);
    s_init_result = result;
    s_progress.status = result == ESP_OK ? FIND_MY_TRANSPORT_IDLE : FIND_MY_TRANSPORT_FAILED;
    s_progress.last_result = result;
    s_init_state = FIND_MY_INIT_FINISHED;
    taskEXIT_CRITICAL(&s_state_lock);

    if (result == ESP_OK) {
        xEventGroupSetBits(s_events, FIND_MY_EVENT_SEND_DONE);
        ESP_LOGI(TAG, "ready: modem=%08" PRIX32 ", interval=%dms, dwell=%dms",
                 (uint32_t)CONFIG_FIND_MY_TRANSPORT_MODEM_ID,
                 CONFIG_FIND_MY_TRANSPORT_ADV_INTERVAL_MS,
                 CONFIG_FIND_MY_TRANSPORT_SYMBOL_DWELL_MS);
    }
    return result;
}

esp_err_t find_my_transport_send(
    const uint8_t *frame,
    size_t frame_len,
    uint32_t message_id,
    find_my_progress_cb_t progress_cb,
    void *progress_context)
{
    if (frame == NULL || frame_len == 0U || frame_len > (size_t)(UINT32_MAX / 4U)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_init_state != FIND_MY_INIT_FINISHED || s_init_result != ESP_OK) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(s_send_mutex, 0) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }

    find_my_schedule_t schedule;
    if (!find_my_schedule_init(
            &schedule,
            (uint32_t)(frame_len * FIND_MY_TRANSPORT_SYMBOLS_PER_BYTE),
            CONFIG_FIND_MY_TRANSPORT_HEADER_REPEATS,
            esp_random(), esp_random())) {
        xSemaphoreGive(s_send_mutex);
        return ESP_ERR_INVALID_SIZE;
    }

    xEventGroupClearBits(s_events, FIND_MY_EVENT_CANCEL | FIND_MY_EVENT_SEND_DONE);
    taskENTER_CRITICAL(&s_state_lock);
    s_send_task = xTaskGetCurrentTaskHandle();
    s_progress.status = FIND_MY_TRANSPORT_SENDING;
    s_progress.message_id = message_id;
    s_progress.total_symbols = schedule.transmissions;
    s_progress.completed_symbols = 0;
    s_progress.current_symbol_index = UINT32_MAX;
    s_progress.current_symbol_value = 0;
    s_progress.cancel_requested = false;
    s_progress.last_result = ESP_OK;
    taskEXIT_CRITICAL(&s_state_lock);
    notify_progress(progress_cb, progress_context);

    ESP_LOGI(TAG,
             "message %" PRIu32 " pass: %" PRIu32
             " transmissions, header=%dx, body start=%" PRIu32
             " step=%" PRIu32,
             message_id, schedule.transmissions,
             CONFIG_FIND_MY_TRANSPORT_HEADER_REPEATS,
             schedule.body_start, schedule.body_step);

    esp_err_t result = ESP_OK;
    for (uint32_t ordinal = 0;
         ordinal < schedule.transmissions && result == ESP_OK;
         ++ordinal) {
        if ((xEventGroupGetBits(s_events) & FIND_MY_EVENT_CANCEL) != 0U) {
            result = ESP_ERR_INVALID_STATE;
            break;
        }

        uint32_t symbol_index = UINT32_MAX;
        if (!find_my_schedule_symbol_at(&schedule, ordinal, &symbol_index)) {
            result = ESP_FAIL;
            break;
        }
        const size_t byte_index = symbol_index
            / FIND_MY_TRANSPORT_SYMBOLS_PER_BYTE;
        const uint32_t offset = symbol_index
            % FIND_MY_TRANSPORT_SYMBOLS_PER_BYTE;
        const uint8_t shift = (uint8_t)(6U - offset * 2U);
        const uint8_t symbol = (uint8_t)((frame[byte_index] >> shift) & 0x03U);

        taskENTER_CRITICAL(&s_state_lock);
        s_progress.current_symbol_index = symbol_index;
        s_progress.current_symbol_value = symbol;
        taskEXIT_CRITICAL(&s_state_lock);

        result = prepare_symbol(symbol_index, message_id, symbol);
        if (result == ESP_OK) {
            result = advertise_prepared_symbol();
        }
        if (result == ESP_OK) {
            taskENTER_CRITICAL(&s_state_lock);
            s_progress.completed_symbols++;
            taskEXIT_CRITICAL(&s_state_lock);
            notify_progress(progress_cb, progress_context);
        }
    }

    esp_err_t stop_result = stop_advertising_from_sender();
    if (result == ESP_OK && stop_result != ESP_OK) {
        result = stop_result;
    }

    bool cancelled = (xEventGroupGetBits(s_events) & FIND_MY_EVENT_CANCEL) != 0U;
    taskENTER_CRITICAL(&s_state_lock);
    s_progress.current_symbol_index = UINT32_MAX;
    s_progress.cancel_requested = cancelled;
    s_progress.last_result = result;
    if (cancelled && result == ESP_ERR_INVALID_STATE) {
        s_progress.status = FIND_MY_TRANSPORT_CANCELLED;
    } else if (result == ESP_OK) {
        s_progress.status = FIND_MY_TRANSPORT_COMPLETE;
    } else {
        s_progress.status = FIND_MY_TRANSPORT_FAILED;
    }
    s_send_task = NULL;
    taskEXIT_CRITICAL(&s_state_lock);

    xEventGroupSetBits(s_events, FIND_MY_EVENT_SEND_DONE);
    xSemaphoreGive(s_send_mutex);
    notify_progress(progress_cb, progress_context);
    return result;
}

void find_my_transport_cancel(void)
{
    if (s_events == NULL) {
        return;
    }

    taskENTER_CRITICAL(&s_state_lock);
    if (s_progress.status == FIND_MY_TRANSPORT_SENDING ||
        s_progress.status == FIND_MY_TRANSPORT_CANCELLING) {
        s_progress.status = FIND_MY_TRANSPORT_CANCELLING;
        s_progress.cancel_requested = true;
        taskEXIT_CRITICAL(&s_state_lock);
        xEventGroupSetBits(s_events, FIND_MY_EVENT_CANCEL);
        return;
    }
    taskEXIT_CRITICAL(&s_state_lock);
}

esp_err_t find_my_transport_stop(void)
{
    if (s_init_state != FIND_MY_INIT_FINISHED || s_init_result != ESP_OK) {
        return ESP_ERR_INVALID_STATE;
    }

    TaskHandle_t sender;
    bool active;
    taskENTER_CRITICAL(&s_state_lock);
    sender = s_send_task;
    active = s_progress.status == FIND_MY_TRANSPORT_SENDING ||
             s_progress.status == FIND_MY_TRANSPORT_CANCELLING;
    taskEXIT_CRITICAL(&s_state_lock);

    if (!active) {
        return ESP_OK;
    }
    find_my_transport_cancel();
    if (sender == xTaskGetCurrentTaskHandle()) {
        return ESP_ERR_INVALID_STATE;
    }

    EventBits_t bits = xEventGroupWaitBits(
        s_events,
        FIND_MY_EVENT_SEND_DONE,
        pdFALSE,
        pdFALSE,
        portMAX_DELAY);
    return (bits & FIND_MY_EVENT_SEND_DONE) != 0U ? ESP_OK : ESP_ERR_TIMEOUT;
}

bool find_my_transport_is_sending(void)
{
    find_my_transport_status_t status = find_my_transport_get_status();
    return status == FIND_MY_TRANSPORT_SENDING || status == FIND_MY_TRANSPORT_CANCELLING;
}

find_my_transport_status_t find_my_transport_get_status(void)
{
    find_my_transport_status_t status;
    taskENTER_CRITICAL(&s_state_lock);
    status = s_progress.status;
    taskEXIT_CRITICAL(&s_state_lock);
    return status;
}

esp_err_t find_my_transport_get_progress(find_my_transport_progress_t *out_progress)
{
    if (out_progress == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    copy_progress(out_progress);
    return ESP_OK;
}

uint32_t find_my_transport_modem_id(void)
{
    return (uint32_t)CONFIG_FIND_MY_TRANSPORT_MODEM_ID;
}
