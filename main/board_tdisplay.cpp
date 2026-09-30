#include "board_tdisplay.h"

#include "board.h"
#include "display.h"

#include <algorithm>
#include <iterator>

#include <esp_adc/adc_cali.h>
#include <esp_adc/adc_cali_scheme.h>
#include <esp_adc/adc_oneshot.h>
#include <esp_log.h>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

namespace {

constexpr TickType_t kDebounceTicks = pdMS_TO_TICKS(40);
constexpr uint32_t kDisplayButtonMask = 1U << 0;
constexpr uint32_t kDispersionButtonMask = 1U << 1;
constexpr uint32_t kAllButtonMasks =
    kDisplayButtonMask | kDispersionButtonMask;
#if CONFIG_BOARD_HELTEC_V3
constexpr adc_atten_t kPowerAdcAttenuation = ADC_ATTEN_DB_2_5;
constexpr uint32_t kPowerDividerNumerator = 49;
constexpr uint32_t kPowerDividerDenominator = 10;
constexpr int kPowerSenseEnabled = 0;
constexpr uint32_t kPlausibleMaximumMv = 4350;
#else
constexpr adc_atten_t kPowerAdcAttenuation = ADC_ATTEN_DB_12;
constexpr uint32_t kPowerDividerNumerator = 2;
constexpr uint32_t kPowerDividerDenominator = 1;
constexpr int kPowerSenseEnabled = 1;
constexpr uint32_t kPlausibleMaximumMv = 5500;
#endif
constexpr unsigned kPowerSampleCount = 24;
constexpr uint32_t kUsbThresholdMv = 4500;
constexpr uint32_t kPlausibleMinimumMv = 3000;

TaskHandle_t s_button_task;
portMUX_TYPE s_handler_lock = portMUX_INITIALIZER_UNLOCKED;
board_tdisplay_dispersion_handler_t s_dispersion_handler;
void *s_dispersion_context;

SemaphoreHandle_t s_power_lock;
adc_oneshot_unit_handle_t s_power_adc;
adc_cali_handle_t s_power_calibration;
adc_channel_t s_power_channel;
bool s_power_initialized;
bool s_power_calibrated;
int s_power_sense_enabled = kPowerSenseEnabled;

struct ChargePoint {
    uint16_t millivolts;
    uint8_t percent;
};

// Approximate rested single-cell LiPo state of charge. Runtime load, cell age,
// temperature and recent charging all move these values, so the UI deliberately
// presents the result as a compact estimate rather than a fuel-gauge reading.
constexpr ChargePoint kChargeCurve[] = {
    {3300, 0}, {3400, 5}, {3500, 10}, {3600, 20}, {3700, 35},
    {3750, 45}, {3800, 55}, {3850, 65}, {3900, 75},
    {4000, 85}, {4100, 95}, {4200, 100},
};

constexpr uint8_t estimate_battery_percent(uint32_t millivolts)
{
    if (millivolts <= kChargeCurve[0].millivolts)
        return 0;
    for (size_t i = 1; i < std::size(kChargeCurve); ++i) {
        if (millivolts > kChargeCurve[i].millivolts)
            continue;
        const auto &low = kChargeCurve[i - 1];
        const auto &high = kChargeCurve[i];
        const uint32_t span_mv = high.millivolts - low.millivolts;
        const uint32_t span_percent = high.percent - low.percent;
        return static_cast<uint8_t>(
            low.percent + ((millivolts - low.millivolts) * span_percent
                           + span_mv / 2) / span_mv);
    }
    return 100;
}

constexpr board_tdisplay_power_source_t classify_power_source(
    uint32_t millivolts)
{
#if CONFIG_BOARD_HELTEC_V3
    // Heltec senses VBAT, not USB. It has no firmware-readable charge-status
    // pin; never present an inferred charging/USB state as a measured one.
    (void)millivolts;
    return BOARD_TDISPLAY_POWER_BATTERY;
#else
    return millivolts >= kUsbThresholdMv
               ? BOARD_TDISPLAY_POWER_USB
               : BOARD_TDISPLAY_POWER_BATTERY;
#endif
}

static_assert(estimate_battery_percent(3300) == 0);
static_assert(estimate_battery_percent(3700) == 35);
static_assert(estimate_battery_percent(3850) == 65);
static_assert(estimate_battery_percent(4200) == 100);
static_assert(classify_power_source(4200) == BOARD_TDISPLAY_POWER_BATTERY);
#if !CONFIG_BOARD_HELTEC_V3
static_assert(classify_power_source(4500) == BOARD_TDISPLAY_POWER_USB);
#endif

uint32_t approximate_adc_pin_mv(int raw)
{
#if CONFIG_BOARD_HELTEC_V3
    // ESP32-S3 nominal range at 2.5 dB. Curve-fit calibration is preferred.
    return (static_cast<uint32_t>(std::max(raw, 0)) * 1250U + 2047U) / 4095U;
#else
    // Calibration should be available on the verified board. This fallback
    // mirrors the factory firmware's raw/4095 * 3.3 V * 1.1 default-Vref
    // approximation for the ADC pin (the 2:1 divider is applied separately).
    return (static_cast<uint32_t>(std::max(raw, 0)) * 3630U + 2047U) / 4095U;
#endif
}

esp_err_t measure_power_at_level(int level, uint32_t *rail_mv)
{
    esp_err_t err = gpio_set_level(BOARD_BATTERY_ADC_ENABLE_PIN, level);
    if (err != ESP_OK)
        return err;
#if CONFIG_BOARD_HELTEC_V3
    // High impedance divider: allow the off-state/floating ADC node to settle.
    vTaskDelay(pdMS_TO_TICKS(200));
#else
    esp_rom_delay_us(5000);
#endif
    int discarded = 0;
    err = adc_oneshot_read(s_power_adc, s_power_channel, &discarded);
    uint32_t total_raw = 0;
    for (unsigned i = 0; err == ESP_OK && i < kPowerSampleCount; ++i) {
        int raw = 0;
        err = adc_oneshot_read(s_power_adc, s_power_channel, &raw);
        total_raw += static_cast<uint32_t>(std::max(raw, 0));
        esp_rom_delay_us(250);
    }
    if (err != ESP_OK)
        return err;
    const int average = static_cast<int>(
        (total_raw + kPowerSampleCount / 2) / kPowerSampleCount);
    int pin_mv = 0;
    if (s_power_calibrated)
        err = adc_cali_raw_to_voltage(s_power_calibration, average, &pin_mv);
    else
        pin_mv = static_cast<int>(approximate_adc_pin_mv(average));
    if (err == ESP_OK)
        *rail_mv = (static_cast<uint32_t>(std::max(pin_mv, 0))
                    * kPowerDividerNumerator + kPowerDividerDenominator / 2)
                   / kPowerDividerDenominator;
    return err;
}

#if !CONFIG_BOARD_HELTEC_V3
uint32_t pressed_buttons()
{
    uint32_t pressed = 0;
    if (gpio_get_level(BOARD_DISPLAY_BUTTON_PIN) == 0)
        pressed |= kDisplayButtonMask;
    if (gpio_get_level(BOARD_DISPERSION_BUTTON_PIN) == 0)
        pressed |= kDispersionButtonMask;
    return pressed;
}

void IRAM_ATTR button_isr(void *)
{
    BaseType_t task_woken = pdFALSE;
    if (s_button_task)
        vTaskNotifyGiveFromISR(s_button_task, &task_woken);
    if (task_woken == pdTRUE)
        portYIELD_FROM_ISR(task_woken);
}

void button_task(void *)
{
    // Suppress each button independently if it is already held at startup.
    // This is especially important for GPIO0, which is also a boot strap pin.
    uint32_t stable_pressed = pressed_buttons();
    uint32_t armed = kAllButtonMasks & ~stable_pressed;

    for (;;) {
        // Sleep with no periodic polling overhead until either GPIO changes.
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        const uint32_t candidate_pressed = pressed_buttons();
        vTaskDelay(kDebounceTicks > 0 ? kDebounceTicks : 1);
        if (candidate_pressed != pressed_buttons())
            continue; // contact still bouncing; another edge will wake us

        const uint32_t newly_pressed = candidate_pressed & ~stable_pressed;
        const uint32_t newly_released = stable_pressed & ~candidate_pressed;
        stable_pressed = candidate_pressed;
        armed |= newly_released;

        const uint32_t actions = newly_pressed & armed;
        armed &= ~actions;

        if (actions & kDisplayButtonMask)
            display_toggle();

        if (actions & kDispersionButtonMask) {
            board_tdisplay_dispersion_handler_t handler;
            void *context;
            taskENTER_CRITICAL(&s_handler_lock);
            handler = s_dispersion_handler;
            context = s_dispersion_context;
            taskEXIT_CRITICAL(&s_handler_lock);
            if (handler)
                handler(context);
            else
                ESP_LOGW("tdisplay", "dispersion button ignored: sender not ready");
        }
    }
}
#else
void button_task(void *)
{
    // GPIO0 is shared with the USB auto-reset circuit. Act only on a stable
    // release after >=1 second held; ordinary serial pulses cannot send money.
    // A button held at boot must be released before it can authorize anything.
    bool stable_pressed = gpio_get_level(BOARD_DISPERSION_BUTTON_PIN) == 0;
    bool armed = !stable_pressed;
    TickType_t pressed_at = 0;
    for (;;) {
        const bool candidate = gpio_get_level(BOARD_DISPERSION_BUTTON_PIN) == 0;
        if (candidate != stable_pressed) {
            vTaskDelay(kDebounceTicks);
            if (candidate == (gpio_get_level(BOARD_DISPERSION_BUTTON_PIN) == 0)) {
                stable_pressed = candidate;
                if (candidate && armed) {
                    pressed_at = xTaskGetTickCount();
                } else if (!candidate) {
                    if (armed) {
                        if (xTaskGetTickCount() - pressed_at >= pdMS_TO_TICKS(1000)) {
                            board_tdisplay_dispersion_handler_t handler;
                            void *context;
                            taskENTER_CRITICAL(&s_handler_lock);
                            handler = s_dispersion_handler;
                            context = s_dispersion_context;
                            taskEXIT_CRITICAL(&s_handler_lock);
                            if (handler)
                                handler(context);
                        } else {
                            display_toggle();
                        }
                    }
                    armed = true;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
#endif

} // namespace

esp_err_t board_tdisplay_power_init(void)
{
    if (s_power_initialized)
        return ESP_OK;

    if (!s_power_lock)
        s_power_lock = xSemaphoreCreateMutex();
    if (!s_power_lock)
        return ESP_ERR_NO_MEM;

    if (xSemaphoreTake(s_power_lock, portMAX_DELAY) != pdTRUE)
        return ESP_ERR_TIMEOUT;
    if (s_power_initialized) {
        xSemaphoreGive(s_power_lock);
        return ESP_OK;
    }

    gpio_config_t enable_cfg = {};
    enable_cfg.pin_bit_mask = 1ULL << BOARD_BATTERY_ADC_ENABLE_PIN;
    enable_cfg.mode = GPIO_MODE_OUTPUT;
    enable_cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    enable_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    enable_cfg.intr_type = GPIO_INTR_DISABLE;
    esp_err_t err = gpio_config(&enable_cfg);
    if (err == ESP_OK)
        err = gpio_set_level(BOARD_BATTERY_ADC_ENABLE_PIN, !kPowerSenseEnabled);

    adc_unit_t unit = ADC_UNIT_1;
    if (err == ESP_OK)
        err = adc_oneshot_io_to_channel(BOARD_BATTERY_ADC_PIN, &unit,
                                        &s_power_channel);
    if (err == ESP_OK && unit != ADC_UNIT_1)
        err = ESP_ERR_INVALID_ARG;

    if (err == ESP_OK) {
        adc_oneshot_unit_init_cfg_t unit_cfg = {};
        unit_cfg.unit_id = unit;
        unit_cfg.ulp_mode = ADC_ULP_MODE_DISABLE;
        err = adc_oneshot_new_unit(&unit_cfg, &s_power_adc);
    }
    if (err == ESP_OK) {
        adc_oneshot_chan_cfg_t channel_cfg = {};
        channel_cfg.atten = kPowerAdcAttenuation;
        channel_cfg.bitwidth = ADC_BITWIDTH_DEFAULT;
        err = adc_oneshot_config_channel(s_power_adc, s_power_channel,
                                         &channel_cfg);
    }

#if ADC_CALI_SCHEME_CURVE_FITTING_SUPPORTED
    if (err == ESP_OK) {
        adc_cali_curve_fitting_config_t calibration_cfg = {};
        calibration_cfg.unit_id = unit;
        calibration_cfg.chan = s_power_channel;
        calibration_cfg.atten = kPowerAdcAttenuation;
        calibration_cfg.bitwidth = ADC_BITWIDTH_DEFAULT;
        s_power_calibrated = adc_cali_create_scheme_curve_fitting(
            &calibration_cfg, &s_power_calibration) == ESP_OK;
    }
#elif ADC_CALI_SCHEME_LINE_FITTING_SUPPORTED
    if (err == ESP_OK) {
        adc_cali_line_fitting_config_t calibration_cfg = {};
        calibration_cfg.unit_id = unit;
        calibration_cfg.atten = kPowerAdcAttenuation;
        calibration_cfg.bitwidth = ADC_BITWIDTH_DEFAULT;
        const esp_err_t calibration_err =
            adc_cali_create_scheme_line_fitting(&calibration_cfg,
                                                &s_power_calibration);
        s_power_calibrated = calibration_err == ESP_OK;
        if (!s_power_calibrated) {
            ESP_LOGW("tdisplay",
                     "power ADC calibration unavailable (%s); using approximation",
                     esp_err_to_name(calibration_err));
        }
    }
#endif

#if CONFIG_BOARD_HELTEC_V3
    if (err == ESP_OK) {
        // V3/V3.1 directly gate the divider active-low; V3.2 adds an NPN
        // stage and enables it active-high. Probe both without assuming a PCB
        // subrevision that the USB/chip IDs cannot establish.
        uint32_t low_mv = 0, high_mv = 0;
        err = measure_power_at_level(0, &low_mv);
        if (err == ESP_OK)
            err = measure_power_at_level(1, &high_mv);
        if (err == ESP_OK) {
            s_power_sense_enabled = high_mv > low_mv + 100U ? 1 : 0;
            ESP_LOGI("heltec", "battery divider: LOW=%lu HIGH=%lu mV, enable=%s",
                     (unsigned long)low_mv, (unsigned long)high_mv,
                     s_power_sense_enabled ? "HIGH (V3.2)" : "LOW (V3/V3.1)");
        }
        (void)gpio_set_level(BOARD_BATTERY_ADC_ENABLE_PIN, !s_power_sense_enabled);
    }
#endif

    s_power_initialized = err == ESP_OK;
    if (err != ESP_OK && s_power_adc) {
        (void)adc_oneshot_del_unit(s_power_adc);
        s_power_adc = nullptr;
    }
    if (err != ESP_OK)
        (void)gpio_set_level(BOARD_BATTERY_ADC_ENABLE_PIN, !s_power_sense_enabled);
    xSemaphoreGive(s_power_lock);
    if (err != ESP_OK) {
        ESP_LOGE("tdisplay", "power sense init failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI("tdisplay", "power sense ready: enable=GPIO%d adc=GPIO%d%s",
             (int)BOARD_BATTERY_ADC_ENABLE_PIN,
             (int)BOARD_BATTERY_ADC_PIN,
             s_power_calibrated ? " (eFuse calibrated)" : " (approximate)");
    return ESP_OK;
}

esp_err_t board_tdisplay_power_read(board_tdisplay_power_status_t *status)
{
    if (!status)
        return ESP_ERR_INVALID_ARG;
    *status = {};

    esp_err_t err = board_tdisplay_power_init();
    if (err != ESP_OK)
        return err;
    if (xSemaphoreTake(s_power_lock, pdMS_TO_TICKS(250)) != pdTRUE)
        return ESP_ERR_TIMEOUT;

    uint32_t rail_mv = 0;
    err = measure_power_at_level(s_power_sense_enabled, &rail_mv);

    // Disable the divider on every path. Preserve a sampling error over a
    // cleanup error so the caller sees the operation's primary failure.
    const esp_err_t disable_err =
        gpio_set_level(BOARD_BATTERY_ADC_ENABLE_PIN, !s_power_sense_enabled);
    if (err == ESP_OK)
        err = disable_err;

    if (err == ESP_OK) {
        if (rail_mv < kPlausibleMinimumMv || rail_mv > kPlausibleMaximumMv) {
            err = ESP_ERR_INVALID_RESPONSE;
        } else {
            status->millivolts = static_cast<uint16_t>(rail_mv);
            status->calibrated = s_power_calibrated;
            status->sense_enabled_high = s_power_sense_enabled != 0;
            status->source = classify_power_source(rail_mv);
            if (status->source == BOARD_TDISPLAY_POWER_BATTERY)
                status->percent = estimate_battery_percent(rail_mv);
        }
    }

    xSemaphoreGive(s_power_lock);
    return err;
}

esp_err_t board_tdisplay_buttons_init(void)
{
    if (s_button_task)
        return ESP_OK;

#if CONFIG_BOARD_HELTEC_V3
    gpio_config_t cfg = {};
    cfg.pin_bit_mask = 1ULL << BOARD_DISPERSION_BUTTON_PIN;
    cfg.mode = GPIO_MODE_INPUT;
    cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_DISABLE;
    const esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK)
        return err;
    if (xTaskCreate(button_task, "board_button", 4096, nullptr, 2,
                   &s_button_task) != pdPASS)
        return ESP_ERR_NO_MEM;
    ESP_LOGI("heltec", "PRG GPIO0: short press screen; hold 1s/release Find My");
    return ESP_OK;
#else

    gpio_config_t cfg = {};
    cfg.pin_bit_mask = (1ULL << BOARD_DISPLAY_BUTTON_PIN) |
                       (1ULL << BOARD_DISPERSION_BUTTON_PIN);
    cfg.mode = GPIO_MODE_INPUT;
    // GPIO35 cannot use an internal pull-up and both board buttons already
    // have external pull-ups. Keep GPIO0's boot/USB network undisturbed.
    cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_ANYEDGE;

    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK)
        return err;

    err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
        return err;

    err = gpio_isr_handler_add(BOARD_DISPLAY_BUTTON_PIN, button_isr, nullptr);
    if (err == ESP_OK)
        err = gpio_isr_handler_add(BOARD_DISPERSION_BUTTON_PIN,
                                   button_isr, nullptr);
    if (err != ESP_OK) {
        gpio_isr_handler_remove(BOARD_DISPLAY_BUTTON_PIN);
        gpio_isr_handler_remove(BOARD_DISPERSION_BUTTON_PIN);
        return err;
    }

    // Install handlers first. Edges before the task exists are harmless (the
    // ISR sees a null handle), and the task's first sample then accurately
    // suppresses any button that is still held at startup.
    if (xTaskCreate(button_task, "board_buttons", 4096, nullptr, 2,
                    &s_button_task) != pdPASS) {
        s_button_task = nullptr;
        gpio_isr_handler_remove(BOARD_DISPLAY_BUTTON_PIN);
        gpio_isr_handler_remove(BOARD_DISPERSION_BUTTON_PIN);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI("tdisplay", "buttons ready: display=GPIO%d dispersion=GPIO%d",
             (int)BOARD_DISPLAY_BUTTON_PIN,
             (int)BOARD_DISPERSION_BUTTON_PIN);
    return ESP_OK;
#endif
}

void board_tdisplay_set_dispersion_handler(
    board_tdisplay_dispersion_handler_t handler, void *context)
{
    taskENTER_CRITICAL(&s_handler_lock);
    s_dispersion_handler = handler;
    s_dispersion_context = context;
    taskEXIT_CRITICAL(&s_handler_lock);
}
