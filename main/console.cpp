#include "console.h"
#include "board.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#define MAX_COMMANDS 32

struct command_entry {
    const char *name;
    console_cmd_handler_t handler;
    const char *help_text;
};

static struct {
    bool initialized;
    bool started;
    size_t max_line_length;
    size_t task_stack_size;
    int task_priority;
    char *line_buffer;
    std::vector<command_entry> commands;
} s_con;

static std::atomic_bool s_commands_ready{false};

void nucula_console_write(const char *str)
{
    if (str)
        uart_write_bytes(UART_NUM_0, str, strlen(str));
}

void console_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    nucula_console_write(buf);
}

static void cmd_help(const char *arg)
{
    (void)arg;
    nucula_console_write("\r\nAvailable commands:\r\n");
    for (const auto &cmd : s_con.commands) {
        nucula_console_write("  ");
        nucula_console_write(cmd.name);
        if (cmd.help_text) {
            size_t name_len = strlen(cmd.name);
            for (size_t i = name_len; i < 14; i++)
                nucula_console_write(" ");
            nucula_console_write("- ");
            nucula_console_write(cmd.help_text);
        }
        nucula_console_write("\r\n");
    }
}

static void process_command(char *cmd, char *arg)
{
    if (!s_commands_ready.load(std::memory_order_acquire)) {
        nucula_console_write("wallet is still starting; try again shortly\r\n");
        return;
    }

    for (const auto &entry : s_con.commands) {
        if (strcmp(cmd, entry.name) == 0) {
            entry.handler(arg);
            return;
        }
    }
    nucula_console_write("unknown command: ");
    nucula_console_write(cmd);
    nucula_console_write("\r\ntype 'help' for available commands.\r\n");
}

static void parse_and_run(char *line)
{
    while (*line == ' ') line++;
    if (*line == '\0') return;

    char *cmd = line;
    char *arg = nullptr;

    char *space = strchr(line, ' ');
    if (space) {
        *space = '\0';
        arg = space + 1;
        while (*arg == ' ') arg++;
        if (*arg == '\0') arg = nullptr;
    }

    process_command(cmd, arg);
}

static void console_task(void *arg)
{
    (void)arg;
    int pos = 0;

    vTaskDelay(pdMS_TO_TICKS(500));
    nucula_console_write("\r\nfind-my-nuts> ");

    // Read in chunks and batch the echo of printable runs: with per-byte
    // reads and a blocking 1-byte echo write each, a full-speed paste of a
    // ~1 KB token outran the task and overflowed the RX ring, silently
    // dropping bytes mid-token.
    while (1) {
        uint8_t buf[64];
        int len = uart_read_bytes(UART_NUM_0, buf, sizeof(buf),
                                  pdMS_TO_TICKS(20));
        if (len <= 0) continue;

        int echo_from = -1;  // start of the unechoed printable run in buf
        auto flush_echo = [&](int upto) {
            if (echo_from >= 0 && upto > echo_from)
                uart_write_bytes(UART_NUM_0, &buf[echo_from],
                                 upto - echo_from);
            echo_from = -1;
        };

        for (int i = 0; i < len; i++) {
            uint8_t c = buf[i];
            if (c == '\r' || c == '\n') {
                flush_echo(i);
                nucula_console_write("\r\n");
                s_con.line_buffer[pos] = '\0';
                parse_and_run(s_con.line_buffer);
                pos = 0;
                nucula_console_write("find-my-nuts> ");
            } else if (c == 127 || c == '\b') {
                flush_echo(i);
                if (pos > 0) {
                    pos--;
                    nucula_console_write("\b \b");
                }
            } else if (c == 0x03) {
                flush_echo(i);
                nucula_console_write("^C\r\n");
                pos = 0;
                nucula_console_write("find-my-nuts> ");
            } else if (pos < (int)s_con.max_line_length - 1) {
                s_con.line_buffer[pos++] = c;
                if (echo_from < 0)
                    echo_from = i;
            } else {
                flush_echo(i);  // line full: swallow without echo
            }
        }
        flush_echo(len);
    }
}

int console_init(const console_config_t *config)
{
    if (s_con.initialized) return -1;

    console_config_t cfg;
    if (config)
        cfg = *config;
    else
        cfg = CONSOLE_DEFAULT_CONFIG();

    s_con.line_buffer = (char *)malloc(cfg.max_line_length);
    if (!s_con.line_buffer) return -2;
    s_con.max_line_length = cfg.max_line_length;
    s_con.task_stack_size = cfg.task_stack_size;
    s_con.task_priority = cfg.task_priority;

    // UART0 through the on-board USB/UART bridge; the board defines TX/RX.
    uart_config_t uart_config = {
        .baud_rate = BOARD_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_DEFAULT,
        .flags = {},
    };

    if (uart_param_config(UART_NUM_0, &uart_config) != ESP_OK ||
        uart_set_pin(UART_NUM_0, BOARD_UART_TX_PIN, BOARD_UART_RX_PIN,
                     UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        free(s_con.line_buffer);
        return -3;
    }

    if (uart_driver_install(UART_NUM_0,
                            static_cast<int>(cfg.rx_buffer_size),
                            static_cast<int>(cfg.tx_buffer_size),
                            0, nullptr, 0) != ESP_OK) {
        free(s_con.line_buffer);
        return -3;
    }

    console_register_cmd("help", cmd_help, "show this help");
    s_con.initialized = true;
    return 0;
}

int console_register_cmd(const char *name, console_cmd_handler_t handler, const char *help_text)
{
    if (!name || !handler) return -1;
    if (s_con.commands.size() >= MAX_COMMANDS) return -2;
    s_con.commands.push_back({name, handler, help_text});
    return 0;
}

int console_start(void)
{
    if (!s_con.initialized) return -1;
    if (s_con.started) return -2;

    BaseType_t ret = xTaskCreate(console_task, "console",
                                 s_con.task_stack_size, NULL,
                                 s_con.task_priority, NULL);
    if (ret != pdPASS) return -3;

    s_con.started = true;
    return 0;
}

void console_set_ready(void)
{
    s_commands_ready.store(true, std::memory_order_release);
}
