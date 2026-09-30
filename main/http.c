#include "http.h"
#include "wifi.h"

#include <stdlib.h>
#include <string.h>
#include "esp_http_client.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_crt_bundle.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define TAG "http"
#define MAX_RESPONSE_SIZE (32 * 1024)

// ESP-IDF's dynamic-free TLS mode deliberately releases CA/config data after
// a handshake. Reconnecting the same esp_http_client object is therefore not
// a supported lifecycle, and stale keep-alive sockets also add ten-second
// failure delays. Use a fresh, fully cleaned client per attempt. The reclaimed
// pending-token stack leaves ample room for a normal handshake, and one-shot
// ownership removes both pinned transport heap and cross-request state.
static SemaphoreHandle_t s_mutex;         // serializes all HTTP activity

void http_init(void)
{
    if (!s_mutex)
        s_mutex = xSemaphoreCreateMutex();
}

static void http_lock(void)
{
    if (s_mutex)
        xSemaphoreTake(s_mutex, portMAX_DELAY);
}

static void http_unlock(void)
{
    if (s_mutex)
        xSemaphoreGive(s_mutex);
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} response_buf_t;

static esp_err_t on_event(esp_http_client_event_t *evt)
{
    response_buf_t *rb = (response_buf_t *)evt->user_data;
    if (!rb) return ESP_OK;

    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        size_t needed = rb->len + evt->data_len;
        if (needed > MAX_RESPONSE_SIZE) {
            ESP_LOGW(TAG, "response truncated at %d bytes", MAX_RESPONSE_SIZE);
            return ESP_OK;
        }
        if (needed >= rb->cap) {
            size_t new_cap = rb->cap ? rb->cap * 2 : 1024;
            while (new_cap < needed + 1) new_cap *= 2;
            char *tmp = realloc(rb->buf, new_cap);
            if (!tmp) {
                ESP_LOGE(TAG, "response allocation failed (%u bytes; heap %lu, largest %u)",
                         (unsigned)new_cap,
                         (unsigned long)esp_get_free_heap_size(),
                         (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
                return ESP_ERR_NO_MEM;
            }
            rb->buf = tmp;
            rb->cap = new_cap;
        }
        memcpy(rb->buf + rb->len, evt->data, evt->data_len);
        rb->len += evt->data_len;
        rb->buf[rb->len] = '\0';
    }
    return ESP_OK;
}

static esp_err_t perform_with_timeout(const char *url, esp_http_client_method_t method,
                                      const char *post_data, int post_len,
                                      http_response_t *resp, int timeout_ms)
{
    http_lock();

    // Disable modem sleep only while bytes are actually in flight. This is
    // independent of association/reconnect state and is restored before the
    // HTTP lock is released.
    const bool low_latency = wifi_is_connected();
    if (low_latency)
        wifi_set_low_latency(true);

    response_buf_t rb = {0};
    esp_err_t err = ESP_FAIL;
    long long ms = 0;
    int status = 0;

    // Each attempt owns its entire HTTP/TLS object. A transient transport
    // failure gets one retry with no stale socket, parser, or freed TLS config.
    for (int attempt = 0; attempt < 2; attempt++) {
        free(rb.buf);
        memset(&rb, 0, sizeof(rb));

        esp_http_client_config_t cfg = {
            .url = url,
            .event_handler = on_event,
            .user_data = &rb,
            .timeout_ms = timeout_ms,
            .crt_bundle_attach = esp_crt_bundle_attach,
        };
        esp_http_client_handle_t client = esp_http_client_init(&cfg);
        if (!client) {
            err = ESP_ERR_NO_MEM;
            ESP_LOGE(TAG, "client init failed");
            break;
        }

        esp_http_client_set_method(client, method);
        if (post_data) {
            esp_http_client_set_header(client, "Content-Type", "application/json");
            esp_http_client_set_post_field(client, post_data, post_len);
        }

        int64_t t0 = esp_timer_get_time();
        err = esp_http_client_perform(client);
        ms = (esp_timer_get_time() - t0) / 1000;
        if (err == ESP_OK)
            status = esp_http_client_get_status_code(client);

        // This is the normal one-shot esp_http_client lifecycle. cleanup is
        // safe whether perform kept the socket alive or closed it from a FIN.
        esp_http_client_set_user_data(client, NULL);
        esp_http_client_cleanup(client);

        if (err == ESP_OK)
            break;

        if (attempt == 0)
            ESP_LOGW(TAG, "request failed (%s), retrying with a fresh client",
                     esp_err_to_name(err));
    }

    if (err == ESP_OK) {
        resp->status = status;
        resp->body = rb.buf;
        resp->body_len = rb.len;
        ESP_LOGI(TAG, "%s %s -> %d in %lld ms (%zu B, heap %lu, largest %u)",
                 post_data ? "POST" : "GET", url, resp->status, ms,
                 resp->body_len, (unsigned long)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    } else {
        ESP_LOGE(TAG, "request failed after %lld ms: %s", ms, esp_err_to_name(err));
        free(rb.buf);
        resp->body = NULL;
        resp->body_len = 0;
        resp->status = 0;
    }

    if (low_latency)
        wifi_set_low_latency(false);
    http_unlock();
    return err;
}

void http_close_all(void)
{
    // Requests are one-shot and own their clients under this same mutex. Once
    // the lock is acquired there is no cached socket or TLS state left to drop.
    http_lock();
    http_unlock();
}

static void prewarm_task(void *arg)
{
    char *url = (char *)arg;
    http_response_t resp = {0};
    if (http_get(url, &resp) == ESP_OK)
        http_response_free(&resp);
    free(url);
    vTaskDelete(NULL);
}

void http_prewarm(const char *base_url)
{
    if (!base_url || !base_url[0])
        return;
    size_t n = strlen(base_url) + sizeof("/v1/info");
    char *url = malloc(n);
    if (!url)
        return;
    snprintf(url, n, "%s/v1/info", base_url);
    if (xTaskCreate(prewarm_task, "http_warm", 8192, url, 3, NULL) != pdPASS)
        free(url);
}

esp_err_t http_get(const char *url, http_response_t *resp)
{
    return perform_with_timeout(url, HTTP_METHOD_GET, NULL, 0, resp, 10000);
}

esp_err_t http_post_json(const char *url, const char *json_body,
                         http_response_t *resp)
{
    return perform_with_timeout(url, HTTP_METHOD_POST, json_body,
                                json_body ? (int)strlen(json_body) : 0,
                                resp, 10000);
}

esp_err_t http_post_json_timeout(const char *url, const char *json_body,
                                 http_response_t *resp, int timeout_ms)
{
    return perform_with_timeout(url, HTTP_METHOD_POST, json_body,
                                json_body ? (int)strlen(json_body) : 0,
                                resp, timeout_ms);
}

void http_response_free(http_response_t *resp)
{
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
