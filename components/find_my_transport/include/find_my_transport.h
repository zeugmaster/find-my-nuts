/*
 * Find My byte transport derived from positive-security/send-my (esp-find-my).
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef FIND_MY_TRANSPORT_H
#define FIND_MY_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIND_MY_TRANSPORT_SYMBOLS_PER_BYTE 4U
#define FIND_MY_TRANSPORT_CANDIDATES_PER_SYMBOL 4U

/** Lifecycle state of the most recent (or current) blocking send. */
typedef enum {
    FIND_MY_TRANSPORT_UNINITIALIZED = 0,
    FIND_MY_TRANSPORT_IDLE,
    FIND_MY_TRANSPORT_SENDING,
    FIND_MY_TRANSPORT_CANCELLING,
    FIND_MY_TRANSPORT_COMPLETE,
    FIND_MY_TRANSPORT_CANCELLED,
    FIND_MY_TRANSPORT_FAILED,
} find_my_transport_status_t;

/** A coherent snapshot of send progress. */
typedef struct {
    find_my_transport_status_t status;
    uint32_t message_id;
    uint32_t total_symbols;
    uint32_t completed_symbols;
    uint32_t current_symbol_index;
    uint8_t current_symbol_value;
    bool advertising;
    bool cancel_requested;
    esp_err_t last_result;
} find_my_transport_progress_t;

/**
 * Called synchronously by find_my_transport_send() on the caller's task.
 * The callback may inspect or cancel the transport, but must not recursively
 * call find_my_transport_send() or block waiting for find_my_transport_stop().
 */
typedef void (*find_my_progress_cb_t)(
    const find_my_transport_progress_t *progress,
    void *context);

/**
 * Initialize and retain the ESP32 BLE controller and Bluedroid host.
 *
 * This function is idempotent. The component owns the BLE GAP callback and is
 * intended for firmware where no other component uses BLE advertising.
 */
esp_err_t find_my_transport_init(void);

/**
 * Send one robust pass of an immutable byte frame as MSB-first 2-bit symbols.
 *
 * The call blocks for the complete transmission and must therefore run on a
 * caller-owned worker task. The input is never modified or retained after the
 * function returns. message_id is supplied by the caller and must be unique
 * for different frame contents. The FMN1 header is repeated and distributed
 * through the pass; body symbols are each sent once in a freshly randomized
 * order. Only one send may be active at a time.
 */
esp_err_t find_my_transport_send(
    const uint8_t *frame,
    size_t frame_len,
    uint32_t message_id,
    find_my_progress_cb_t progress_cb,
    void *progress_context);

/** Request cooperative cancellation of the active blocking send. */
void find_my_transport_cancel(void);

/**
 * Cancel an active send and wait until its worker has stopped advertising.
 * Do not call this from that send's progress callback or worker task.
 */
esp_err_t find_my_transport_stop(void);

/** True while a send is active, including while it is cancelling. */
bool find_my_transport_is_sending(void);

/** Return the current lifecycle state. */
find_my_transport_status_t find_my_transport_get_status(void);

/** Copy a coherent progress snapshot into out_progress. */
esp_err_t find_my_transport_get_progress(find_my_transport_progress_t *out_progress);

/** Return the public, non-secret routing identifier configured in menuconfig. */
uint32_t find_my_transport_modem_id(void);

#ifdef __cplusplus
}
#endif

#endif /* FIND_MY_TRANSPORT_H */
