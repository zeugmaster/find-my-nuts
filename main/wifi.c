#include "wifi.h"
#include "wifi_config.h"
#include "http.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_coexist.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

/* Number of fast back-to-back retries the event handler will fire on its own
 * before handing off to the periodic supervisor. After this, the supervisor
 * reconnects on a fixed cadence and never gives up. */
#define FAST_RETRY_COUNT      3
#define SUPERVISOR_PERIOD_MS  30000
#define WIFI_FIND_MY_GUARD_BIT BIT1

static const char *TAG = "wifi";
static EventGroupHandle_t s_event_group;
static TaskHandle_t s_supervisor_task;
static int s_retry_count;

static bool event_bit_is_set(EventBits_t bit)
{
    return s_event_group && (xEventGroupGetBits(s_event_group) & bit) != 0;
}

static void wifi_supervisor_task(void *arg)
{
    (void)arg;
    bool was_connected = wifi_is_connected();
    for (;;) {
        // WIFI_EVENT_STA_START owns the initial connect, and disconnect events
        // own the fast retries. Starting this loop immediately used to race
        // that first attempt and emit ESP_ERR_WIFI_CONN at every boot.
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(SUPERVISOR_PERIOD_MS));

        const bool connected = wifi_is_connected();
        if (!connected) {
            if (was_connected) {
                /* Falling edge: the cached HTTP connections are dead. Done
                 * here (not in the event handler) because closing blocks on
                 * the HTTP mutex until any in-flight request finishes. */
                http_close_all();
            }
            if (!event_bit_is_set(WIFI_FIND_MY_GUARD_BIT)) {
                ESP_LOGI(TAG, "supervisor: attempting reconnect");
                esp_err_t err = esp_wifi_connect();
                if (err != ESP_OK && err != ESP_ERR_WIFI_CONN)
                    ESP_LOGW(TAG, "esp_wifi_connect() returned %d", err);
            } else {
                ESP_LOGI(TAG, "supervisor: reconnect deferred for Find My");
            }
        }
        was_connected = connected;
    }
}

static void event_handler(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event =
            (wifi_event_sta_disconnected_t *)data;
        ESP_LOGW(TAG, "disconnected, reason: %d", event->reason);
        xEventGroupClearBits(s_event_group, WIFI_CONNECTED_BIT);
        if (!event_bit_is_set(WIFI_FIND_MY_GUARD_BIT)
            && s_retry_count < FAST_RETRY_COUNT) {
            s_retry_count++;
            ESP_LOGI(TAG, "fast retry (%d/%d)", s_retry_count, FAST_RETRY_COUNT);
            esp_wifi_connect();
        } else if (event_bit_is_set(WIFI_FIND_MY_GUARD_BIT)) {
            ESP_LOGI(TAG, "reconnect deferred while Find My is active");
        }
        /* After FAST_RETRY_COUNT the supervisor task takes over. */
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "connected, ip: " IPSTR, IP2STR(&event->ip_info.ip));

        /* Some networks hand out an IP but no usable DNS server (the DHCP
         * lease omits it). lwIP then fails name resolution instantly with
         * EAI_FAIL, so the mints never resolve. If the main DNS slot is
         * empty, install public resolvers as a fallback. */
        esp_netif_dns_info_t dns = {0};
        esp_netif_get_dns_info(event->esp_netif, ESP_NETIF_DNS_MAIN, &dns);
        ESP_LOGI(TAG, "got ip=" IPSTR " gw=" IPSTR " dns=" IPSTR,
                 IP2STR(&event->ip_info.ip), IP2STR(&event->ip_info.gw),
                 IP2STR(&dns.ip.u_addr.ip4));
        if (dns.ip.u_addr.ip4.addr == 0) {
            esp_netif_dns_info_t main_dns = { .ip.type = ESP_IPADDR_TYPE_V4 };
            esp_netif_dns_info_t backup_dns = { .ip.type = ESP_IPADDR_TYPE_V4 };
            main_dns.ip.u_addr.ip4.addr   = esp_ip4addr_aton("1.1.1.1");
            backup_dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("8.8.8.8");
            esp_netif_set_dns_info(event->esp_netif, ESP_NETIF_DNS_MAIN,
                                   &main_dns);
            esp_netif_set_dns_info(event->esp_netif, ESP_NETIF_DNS_BACKUP,
                                   &backup_dns);
            ESP_LOGW(TAG, "no DNS from DHCP; using fallback 1.1.1.1 / 8.8.8.8");
        }

        s_retry_count = 0;
        xEventGroupSetBits(s_event_group, WIFI_CONNECTED_BIT);
    }
}

/* Log-and-return instead of ESP_ERROR_CHECK: a failed WiFi bring-up must
 * degrade to offline operation (the app tolerates ESP_FAIL), not abort()
 * the whole wallet. */
#define WIFI_RETURN_ON_ERROR(x) do {                                   \
        esp_err_t err_ = (x);                                          \
        if (err_ != ESP_OK) {                                          \
            ESP_LOGE(TAG, "%s failed: %s", #x, esp_err_to_name(err_)); \
            return err_;                                               \
        }                                                              \
    } while (0)

esp_err_t wifi_init(void)
{
    if (WIFI_SSID[0] == '\0') {
        ESP_LOGW(TAG, "Wi-Fi is not configured; continuing offline");
        return ESP_ERR_NOT_FOUND;
    }

    s_event_group = xEventGroupCreate();
    if (!s_event_group)
        return ESP_ERR_NO_MEM;

    WIFI_RETURN_ON_ERROR(esp_netif_init());
    WIFI_RETURN_ON_ERROR(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    WIFI_RETURN_ON_ERROR(esp_wifi_init(&cfg));

    WIFI_RETURN_ON_ERROR(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    WIFI_RETURN_ON_ERROR(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    WIFI_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA));
    WIFI_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    WIFI_RETURN_ON_ERROR(esp_wifi_start());

    /* Spawn the supervisor before we even check the initial result. The fast
     * retries from event_handler may already be exhausted by the time we
     * return; the supervisor takes it from there. */
    /* 4096: the supervisor also runs http_close_all (TLS teardown) now, and
     * its high-water mark was already down to ~270 bytes at 2048. */
    BaseType_t ok = xTaskCreate(wifi_supervisor_task, "wifi_sup",
                                4096, NULL, 3, &s_supervisor_task);
    if (ok != pdPASS)
        ESP_LOGE(TAG, "failed to spawn wifi_supervisor_task");

    ESP_LOGI(TAG, "connecting to \"%s\"...", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_event_group,
                                           WIFI_CONNECTED_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        /* Battery device: let the radio doze between DTIM beacons. Costs
         * ~100-300 ms first-packet latency; wifi_set_low_latency(true)
         * can lift it temporarily for a latency-sensitive network request. */
        esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "not connected within 15s; supervisor continues retrying");
    return ESP_FAIL;
}

bool wifi_is_connected(void)
{
    return event_bit_is_set(WIFI_CONNECTED_BIT);
}

void wifi_set_low_latency(bool on)
{
    esp_wifi_set_ps(on ? WIFI_PS_NONE : WIFI_PS_MIN_MODEM);
}

void wifi_set_find_my_radio_guard(bool active)
{
    if (!s_event_group)
        return;

    if (active)
        xEventGroupSetBits(s_event_group, WIFI_FIND_MY_GUARD_BIT);
    else
        xEventGroupClearBits(s_event_group, WIFI_FIND_MY_GUARD_BIT);

    esp_err_t err = esp_coex_preference_set(
        active ? ESP_COEX_PREFER_BT : ESP_COEX_PREFER_BALANCE);
    if (err != ESP_OK)
        ESP_LOGW(TAG, "coexistence preference failed: %s", esp_err_to_name(err));

    if (!active && s_supervisor_task)
        xTaskNotifyGive(s_supervisor_task);
}

EventGroupHandle_t wifi_get_event_group(void)
{
    return s_event_group;
}
