#include <cstdio>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>
#include "secp256k1.h"
#include "crypto.h"
#include "crypto_test.h"
#include "crypto_bls_test.h"
#include "wifi.h"
#include "http.h"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "keyset.hpp"
#include "unit.hpp"
#include "console.h"
#include "display.h"
#include "board_tdisplay.h"
#include "bip39.h"
#include "wallet_store.hpp"
#include "proof_distribution.hpp"
#include "find_my_policy.hpp"
#include "find_my_schedule.h"
#include "find_my_transport.h"
#include "find_my_outbox.hpp"
#include "find_my_wallet.hpp"
#include "ui.h"

#define TAG "nucula"

// -------------------------------------------------------------------------
// Console commands
// -------------------------------------------------------------------------

// Defined below; used by cmd_mint's info subcommand too.
static cashu::Wallet *resolve_wallet(const char *idx_str);

// Trailing options shared by the money commands: "u=<unit> m=<method>
// a=<amount> w=<mint idx>" in any order. A bare integer token is still
// accepted as the mint index (the old positional syntax).
struct CmdOpts {
    std::string unit;     // empty = Wallet::default_unit()
    std::string method;   // empty = bolt11
    int amount = -1;      // a=, only meaningful where documented
    std::string idx;      // empty = auto-resolve
    std::string distribution; // d=<amount[-amount]|amountxcount...>
    bool find_my = false; // recognized only to explain the retired claim mode
};

static bool parse_cmd_opts(const char *p, CmdOpts &out)
{
    while (p && *p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *end = strchr(p, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        std::string tok(p, len);
        if (tok.rfind("u=", 0) == 0) {
            out.unit = cashu::normalize_unit(tok.substr(2));
            if (!cashu::unit_token_valid(out.unit.c_str())) {
                console_printf("error: bad unit '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("m=", 0) == 0) {
            out.method = tok.substr(2);
            if (!cashu::unit_token_valid(out.method.c_str())) {
                console_printf("error: bad method '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("a=", 0) == 0) {
            out.amount = atoi(tok.c_str() + 2);
            if (out.amount <= 0) {
                console_printf("error: bad amount '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("w=", 0) == 0) {
            out.idx = tok.substr(2);
        } else if (tok.rfind("d=", 0) == 0) {
            out.distribution = tok;
        } else if (tok == "findmy") {
            out.find_my = true;
        } else if (tok.find_first_not_of("0123456789") == std::string::npos) {
            out.idx = tok;   // bare integer = mint index (legacy syntax)
        } else {
            console_printf("error: unknown option '%s'\r\n", tok.c_str());
            return false;
        }
        p = end;
    }
    return true;
}

// Print one formatted line per unit held by the wallet, prefix-indented.
// Returns true when any proofs have an unknown keyset ("?" unit).
static bool print_unit_balances(cashu::Wallet *w, const char *prefix,
                                const char *label)
{
    bool unknown = false;
    std::vector<std::string> units;
    w->collect_units(units);
    for (const auto &u : units) {
        if (u == "?") {
            unknown = true;
            continue;
        }
        char amt[48];
        cashu::format_amount(amt, sizeof(amt), w->balance_for_unit(u), u.c_str());
        console_printf("%s%s%s\r\n", prefix, label, amt);
    }
    return unknown;
}

static void cmd_status(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;
    board_tdisplay_power_status_t power = {};
    const esp_err_t power_err = board_tdisplay_power_read(&power);
    console_printf("board:   %s\r\n", BOARD_NAME);
    console_printf("display: %dx%d, %s\r\n", LCD_W, LCD_H,
                   display_is_powered() ? "on" : "off/unavailable");
    console_printf("button:  %s to start/pause Find My\r\n", BOARD_BUTTON_HINT);
    console_printf("wifi:    %s\r\n", wifi_is_connected() ? "connected" : "disconnected");
    if (power_err != ESP_OK || power.source == BOARD_TDISPLAY_POWER_UNKNOWN) {
        console_printf("power:   unavailable (%s)\r\n",
                       esp_err_to_name(power_err));
    } else if (power.source == BOARD_TDISPLAY_POWER_USB) {
        console_printf("power:   USB (%u.%02u V sensed%s)\r\n",
                       (unsigned)(power.millivolts / 1000U),
                       (unsigned)((power.millivolts % 1000U) / 10U),
                       power.calibrated ? ", calibrated" : ", approximate");
    } else {
        console_printf("power:   battery %u%% (%u.%02u V%s)\r\n",
                       (unsigned)power.percent,
                       (unsigned)(power.millivolts / 1000U),
                       (unsigned)((power.millivolts % 1000U) / 10U),
                       power.calibrated ? ", calibrated" : ", approximate");
    }
    auto fm = find_my_nuts::outbox_status();
#if CONFIG_BOARD_HELTEC_V3
    if (power_err == ESP_OK)
        console_printf("sense:   GPIO37 active-%s (auto-detected); no charging-state sensor\r\n",
                       power.sense_enabled_high ? "high" : "low");
#endif
    console_printf("find my: %s, %u/%u slots%s\r\n",
                   fm.paused ? "paused" : (fm.started ? "active" : "stopped"),
                   (unsigned)fm.used_slots, (unsigned)fm.capacity,
                   fm.transmitting ? ", transmitting" : "");
    console_printf("heap:    %lu bytes free\r\n",
                   (unsigned long)esp_get_free_heap_size());
    console_printf("unit:    %s (default)\r\n",
                   cashu::Wallet::default_unit().c_str());

    int count = wallet_store_count();
    console_printf("mints:   %d/%d\r\n", count, MAX_MINTS);

    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w) continue;
        console_printf("[%d] %s\r\n", i, w->mint_url().c_str());
        for (const auto &ks : w->keysets())
            if (ks.active)
                console_printf("    active:  %s (%s, %d keys)\r\n",
                               ks.id.c_str(), ks.unit.c_str(),
                               (int)ks.keys.size());
        console_printf("    keysets: %d\r\n", (int)w->keysets().size());
        console_printf("    proofs:  %d\r\n", (int)w->proofs().size());
        if (print_unit_balances(w, "    ", "balance: "))
            nucula_console_write("    warning: proofs with unknown keyset\r\n");
    }
    if (count > 0) {
        std::vector<std::string> units;
        wallet_store_collect_units(units);
        for (const auto &u : units) {
            if (u == "?") continue;
            char amt[48];
            cashu::format_amount(amt, sizeof(amt),
                                 wallet_store_balance_for_unit(u.c_str()),
                                 u.c_str());
            console_printf("total:   %s\r\n", amt);
        }
    }
}

static void cmd_balance(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;
    bool any = false;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w || w->proofs().empty()) continue;
        any = true;
        console_printf("[%s]\r\n", w->mint_url().c_str());
        for (const auto &p : w->proofs()) {
            const std::string *u = w->unit_for_proof(p);
            char amt[48];
            cashu::format_amount(amt, sizeof(amt), p.amount,
                                 u ? u->c_str() : "?");
            console_printf("  %s  (keyset %s)\r\n", amt, p.id.c_str());
        }
        if (print_unit_balances(w, "  ", "subtotal: "))
            nucula_console_write("  warning: proofs with unknown keyset excluded\r\n");
    }
    if (!any) {
        nucula_console_write("no proofs\r\n");
        return;
    }
    std::vector<std::string> units;
    wallet_store_collect_units(units);
    for (const auto &u : units) {
        if (u == "?") continue;
        char amt[48];
        cashu::format_amount(amt, sizeof(amt),
                             wallet_store_balance_for_unit(u.c_str()), u.c_str());
        console_printf("total: %s\r\n", amt);
    }
}

// unit [<name>] — show or set the persisted default unit.
static void cmd_unit(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        console_printf("default unit: %s\r\n",
                       cashu::Wallet::default_unit().c_str());
        std::vector<std::string> units;
        wallet_store_collect_units(units);
        if (!units.empty()) {
            nucula_console_write("held units:");
            for (const auto &u : units)
                console_printf(" %s", u.c_str());
            nucula_console_write("\r\n");
        }
        return;
    }

    // First token only; normalize before validating.
    const char *end = strchr(arg, ' ');
    std::string unit = cashu::normalize_unit(
        end ? std::string(arg, end - arg) : std::string(arg));
    if (!cashu::unit_token_valid(unit.c_str())) {
        nucula_console_write("error: unit must be non-empty [a-z0-9_-]\r\n");
        return;
    }

    // Warn — but allow — when no mint currently backs the unit; keysets
    // may simply not be fetched yet.
    bool backed = false;
    for (int i = 0; i < MAX_MINTS && !backed; i++) {
        auto *w = wallet_store_get(i);
        if (w && w->active_keyset(unit))
            backed = true;
    }

    if (!cashu::Wallet::set_default_unit(unit)) {
        nucula_console_write("error: failed to persist default unit\r\n");
        return;
    }
    console_printf("default unit: %s%s\r\n", unit.c_str(),
                   backed ? "" : " (no mint has an active keyset for it yet)");
    display_refresh();
}

static void cmd_receive(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: receive <cashu token>\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    cashu::Token token;
    if (!cashu::deserialize_token(arg, token)) {
        nucula_console_write("error: failed to decode token\r\n");
        return;
    }

    char amt[48];
    cashu::format_amount(amt, sizeof(amt),
                         cashu::proofs_sum(token.proofs), token.unit.c_str());
    console_printf("token: %s in %d proofs from %s\r\n",
                   amt, (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = wallet_store_get_or_create(token.mint);
    if (!w) {
        console_printf("error: max %d mints, remove one first\r\n", MAX_MINTS);
        return;
    }

    if (w->keysets().empty() || !w->active_keyset(token.unit)) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("swapping...\r\n");
    std::vector<cashu::Proof> received;
    int64_t t0 = esp_timer_get_time();
    if (!w->receive(token, received)) {
        nucula_console_write("error: receive failed\r\n");
        return;
    }
    long long ms = (esp_timer_get_time() - t0) / 1000;

    cashu::format_amount(amt, sizeof(amt),
                         cashu::proofs_sum(received), token.unit.c_str());
    console_printf("received %s in %d proofs (%lld ms)\r\n",
                   amt, (int)received.size(), ms);
    display_refresh();
}

static bool normalize_mint_url(const char *input, std::string &normalized,
                               std::string &error)
{
    normalized.clear();
    error.clear();
    if (!input) {
        error = "empty mint URL";
        return false;
    }

    std::string url(input);
    size_t first = 0;
    while (first < url.size()
           && std::isspace(static_cast<unsigned char>(url[first])))
        ++first;
    size_t last = url.size();
    while (last > first
           && std::isspace(static_cast<unsigned char>(url[last - 1])))
        --last;
    url = url.substr(first, last - first);
    if (url.empty()) {
        error = "empty mint URL";
        return false;
    }

    if (url.find("://") == std::string::npos) {
        url.insert(0, "https://");
    } else if (url.rfind("https://", 0) != 0
               && url.rfind("http://", 0) != 0) {
        error = "mint URL scheme must be https:// or http://";
        return false;
    }

    if (url.size() > 240) {
        error = "mint URL is too long";
        return false;
    }
    for (unsigned char ch : url) {
        if (std::isspace(ch)) {
            error = "mint URL cannot contain whitespace";
            return false;
        }
    }
    if (url.find('?') != std::string::npos
        || url.find('#') != std::string::npos) {
        error = "mint base URL cannot contain a query or fragment";
        return false;
    }

    const size_t authority_start = url.find("://") + 3;
    const size_t authority_end = url.find('/', authority_start);
    const size_t authority_length =
        (authority_end == std::string::npos ? url.size() : authority_end)
        - authority_start;
    if (authority_length == 0) {
        error = "mint URL has no host";
        return false;
    }
    if (url.find('@', authority_start) < authority_start + authority_length) {
        error = "mint URL cannot contain embedded credentials";
        return false;
    }

    while (url.size() > authority_start + authority_length
           && url.back() == '/')
        url.pop_back();

    normalized = std::move(url);
    return true;
}

static void cmd_mint(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0 || strcmp(arg, "list") == 0) {
        int count = wallet_store_count();
        if (count == 0) {
            nucula_console_write("no mints configured\r\n");
            return;
        }
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!wallet_store_get(i)) continue;
            console_printf("[%d] %s  (%d keysets, %lld sat)\r\n",
                           i, wallet_store_get(i)->mint_url().c_str(),
                           (int)wallet_store_get(i)->keysets().size(),
                           (long long)wallet_store_get(i)->balance());
        }
        console_printf("%d/%d slots used\r\n", count, MAX_MINTS);
        return;
    }

    if (strncmp(arg, "add ", 4) == 0) {
        const char *input = arg + 4;
        while (*input == ' ') input++;
        if (strlen(input) == 0) {
            nucula_console_write("usage: mint add <url>\r\n");
            return;
        }
        std::string url;
        std::string error;
        if (!normalize_mint_url(input, url, error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        if (wallet_store_find(url.c_str())) {
            nucula_console_write("mint already added\r\n");
            return;
        }
        if (!wifi_is_connected()) {
            nucula_console_write(
                "error: Wi-Fi is offline; mint was not added\r\n");
            return;
        }
        if (url != input)
            console_printf("using canonical URL: %s\r\n", url.c_str());

        auto *w = wallet_store_get_or_create(url);
        if (!w) {
            console_printf("error: no free mint slot or URL persistence failed "
                           "(max %d)\r\n", MAX_MINTS);
            return;
        }
        const int slot = w->nvs_slot();
        nucula_console_write("validating mint keysets...\r\n");
        if (!w->load_keysets()) {
            if (wallet_store_remove(slot)) {
                nucula_console_write(
                    "error: keyset validation failed; mint was not added\r\n");
            } else {
                console_printf(
                    "error: keyset validation failed and slot %d rollback "
                    "failed; run 'mint remove %d' before reboot\r\n",
                    slot, slot);
            }
            display_refresh();
            return;
        }

        console_printf("added mint [%d]: %s\r\n", slot, url.c_str());
        display_refresh();
        return;
    }

    if (strncmp(arg, "info", 4) == 0 && (arg[4] == '\0' || arg[4] == ' ')) {
        const char *idx = arg + 4;
        while (*idx == ' ') idx++;
        cashu::Wallet *w = resolve_wallet(*idx ? idx : nullptr);
        if (!w) return;
        if (!w->mint_info()) {
            if (!wifi_is_connected()) {
                nucula_console_write("error: not connected to wifi\r\n");
                return;
            }
            nucula_console_write("loading mint info...\r\n");
            if (!w->load_mint_info()) {
                nucula_console_write("error: failed to load mint info\r\n");
                return;
            }
        }
        const cashu::MintInfo *info = w->mint_info();
        console_printf("%s\r\n", info->name.empty() ? w->mint_url().c_str()
                                                    : info->name.c_str());
        auto print_rows = [](const char *label,
                             const std::vector<cashu::MintMethodSetting> &rows) {
            console_printf("%s\r\n", label);
            if (rows.empty()) {
                nucula_console_write("  (none advertised)\r\n");
                return;
            }
            for (const auto &r : rows) {
                char line[96];
                int n = snprintf(line, sizeof(line), "  %s %s",
                                 r.method.c_str(), r.unit.c_str());
                if (r.method_name && n > 0 && n < (int)sizeof(line))
                    n += snprintf(line + n, sizeof(line) - n, " \"%s\"",
                                  r.method_name->c_str());
                if ((r.min_amount || r.max_amount) && n > 0 && n < (int)sizeof(line))
                    snprintf(line + n, sizeof(line) - n, " (%lld..%lld)",
                             r.min_amount ? (long long)*r.min_amount : 0LL,
                             r.max_amount ? (long long)*r.max_amount : 0LL);
                console_printf("%s\r\n", line);
            }
        };
        print_rows("mint:", info->mint_methods);
        print_rows("melt:", info->melt_methods);
        return;
    }

    if (strncmp(arg, "remove ", 7) == 0) {
        const char *id = arg + 7;
        while (*id == ' ') id++;

        int slot = -1;
        if (strlen(id) == 1 && id[0] >= '0' && id[0] < ('0' + MAX_MINTS))
            slot = id[0] - '0';

        cashu::Wallet *w = wallet_store_get(slot);
        if (!w) {
            w = wallet_store_find(id);
            if (w)
                slot = w->nvs_slot();
        }

        if (!w) {
            nucula_console_write("mint not found\r\n");
            return;
        }

        const std::string removed_url = w->mint_url();
        const long long removed_balance = w->balance();
        const int removed_proofs = (int)w->proofs().size();
        if (!wallet_store_remove(slot)) {
            console_printf("error: failed to remove mint [%d]; NVS unchanged\r\n",
                           slot);
            return;
        }
        console_printf("removed [%d] %s (%lld sat, %d proofs erased)\r\n",
                       slot, removed_url.c_str(), removed_balance,
                       removed_proofs);
        display_refresh();
        return;
    }

    nucula_console_write("usage: mint [list|add <url>|remove <index|url>|info [idx]]\r\n");
}

// Caller must hold the wallet_store guard (all cmd_* callers do).
static cashu::Wallet *resolve_wallet(const char *idx_str)
{
    int count = wallet_store_count();
    if (count == 0) {
        nucula_console_write("error: no mints configured\r\n");
        return nullptr;
    }
    if (idx_str && *idx_str) {
        int slot = atoi(idx_str);
        if (slot >= 0 && slot < MAX_MINTS && wallet_store_get(slot))
            return wallet_store_get(slot);
        nucula_console_write("error: invalid mint index\r\n");
        return nullptr;
    }
    if (count == 1) {
        for (int i = 0; i < MAX_MINTS; i++)
            if (wallet_store_get(i)) return wallet_store_get(i);
    }
    nucula_console_write("error: multiple mints, specify index\r\n");
    for (int i = 0; i < MAX_MINTS; i++) {
        if (!wallet_store_get(i)) continue;
        console_printf("  [%d] %s\r\n", i, wallet_store_get(i)->mint_url().c_str());
    }
    return nullptr;
}

static void cmd_invoice(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: invoice <amount> [u=<unit>] [m=<method>] [w=<mint_idx>]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    int amount = atoi(arg);
    if (amount <= 0) {
        nucula_console_write("error: amount must be positive\r\n");
        return;
    }

    CmdOpts opts;
    if (!parse_cmd_opts(strchr(arg, ' '), opts))
        return;
    const std::string unit = opts.unit.empty() ? cashu::Wallet::default_unit()
                                               : opts.unit;
    const std::string method = opts.method.empty() ? std::string("bolt11")
                                                   : opts.method;

    cashu::Wallet *w = resolve_wallet(opts.idx.empty() ? nullptr
                                                       : opts.idx.c_str());
    if (!w) return;

    if (w->keysets().empty() || !w->active_keyset(unit)) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
        if (!w->active_keyset(unit)) {
            console_printf("error: mint has no active %s keyset\r\n",
                           unit.c_str());
            return;
        }
    }

    nucula_console_write("requesting mint quote...\r\n");
    cashu::MintQuote quote;
    if (!w->request_mint_quote(amount, unit, method, quote)) {
        nucula_console_write("error: failed to get mint quote\r\n");
        return;
    }

    // For bolt11 `request` is an invoice; for custom methods it is an
    // opaque payment target (URL, account reference) — print verbatim.
    nucula_console_write(method == "bolt11" ? "pay this invoice:\r\n"
                                            : "payment request:\r\n");
    nucula_console_write(quote.request.c_str());
    nucula_console_write("\r\n");
    console_printf("quote: %s\r\n", quote.quote.c_str());
    char amt[48];
    cashu::format_amount(amt, sizeof(amt), quote.amount, quote.unit.c_str());
    console_printf("amount: %s\r\n", amt);
    if (method == "bolt11")
        nucula_console_write("then run: claim <quote_id>\r\n");
    else
        console_printf("then run: claim %s m=%s\r\n",
                       quote.quote.c_str(), method.c_str());
}

static void cmd_claim(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: claim <quote_id> [m=<method>] [w=<mint_idx>] "
                             "[d=<distribution>]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    // Split quote_id and optional trailing options
    std::string quote_id;
    CmdOpts opts;
    const char *space = strchr(arg, ' ');
    if (space) {
        quote_id = std::string(arg, space - arg);
        if (!parse_cmd_opts(space, opts))
            return;
    } else {
        quote_id = arg;
    }
    if (opts.find_my) {
        nucula_console_write(
            "error: 'claim ... findmy' is no longer supported; claim into the "
            "wallet, then " BOARD_BUTTON_HINT " or run 'findmy resume' to select one "
            "random proof\r\n");
        return;
    }
    const std::string method = opts.method.empty() ? std::string("bolt11")
                                                   : opts.method;

    cashu::Wallet *w = nullptr;
    cashu::MintQuote quote;

    if (!opts.idx.empty()) {
        w = resolve_wallet(opts.idx.c_str());
        if (!w) return;
        if (!w->check_mint_quote(quote_id, method, quote)) {
            nucula_console_write("error: quote not found on this mint\r\n");
            return;
        }
    } else {
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!wallet_store_get(i)) continue;
            if (wallet_store_get(i)->check_mint_quote(quote_id, method, quote)) {
                w = wallet_store_get(i);
                break;
            }
        }
    }

    if (!w) {
        nucula_console_write("error: quote not found on any mint\r\n");
        return;
    }

    // Claimable = amount_paid - amount_issued on current mints; legacy
    // bolt11 mints only expose state, where PAID means the full amount.
    int claimable = quote.mintable();
    if (claimable <= 0) {
        if (quote.state == "UNPAID")
            nucula_console_write("invoice not paid yet\r\n");
        else if (quote.state == "ISSUED")
            nucula_console_write("tokens already claimed\r\n");
        else if (quote.amount_paid && quote.amount_issued)
            nucula_console_write("nothing mintable (paid amount fully issued)\r\n");
        else
            console_printf("unexpected state: %s\r\n", quote.state.c_str());
        return;
    }

    const std::string unit = quote.unit.empty() ? std::string("sat") : quote.unit;
    if (w->keysets().empty() || !w->active_keyset(unit)) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
        if (!w->active_keyset(unit)) {
            console_printf("error: mint has no active %s keyset\r\n",
                           unit.c_str());
            return;
        }
    }

    std::vector<int> output_amounts;
    if (opts.distribution.empty()) {
        output_amounts = cashu::Wallet::split_amount(claimable);
    } else {
        std::string distribution_error;
        if (!cashu::parse_proof_distribution(
                opts.distribution, claimable,
                CONFIG_NUCULA_MAX_DISTRIBUTION_PROOFS,
                output_amounts, distribution_error)) {
            console_printf("error: %s\r\n", distribution_error.c_str());
            return;
        }
    }

    console_printf("minting %d token proof%s...\r\n",
                   (int)output_amounts.size(),
                   output_amounts.size() == 1 ? "" : "s");
    if (!w->mint_tokens(quote, output_amounts)) {
        nucula_console_write("error: minting failed\r\n");
        return;
    }

    char amt[48];
    cashu::format_amount(amt, sizeof(amt), claimable,
                         quote.unit.empty() ? "sat" : quote.unit.c_str());
    console_printf("minted %s in %d proof%s\r\n", amt,
                   (int)output_amounts.size(),
                   output_amounts.size() == 1 ? "" : "s");

    display_refresh();
}

static void cmd_melt(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: melt <request> [u=<unit>] [m=<method>] "
                             "[a=<amount>] [w=<mint_idx>]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    // Split the payment request and optional trailing options
    std::string request;
    CmdOpts opts;
    const char *space = strchr(arg, ' ');
    if (space) {
        request = std::string(arg, space - arg);
        if (!parse_cmd_opts(space, opts))
            return;
    } else {
        request = arg;
    }
    const std::string unit = opts.unit.empty() ? cashu::Wallet::default_unit()
                                               : opts.unit;
    const std::string method = opts.method.empty() ? std::string("bolt11")
                                                   : opts.method;

    cashu::Wallet *w = resolve_wallet(opts.idx.empty() ? nullptr
                                                       : opts.idx.c_str());
    if (!w) return;

    if (w->keysets().empty() || !w->active_keyset(unit)) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
        if (!w->active_keyset(unit)) {
            console_printf("error: mint has no active %s keyset\r\n",
                           unit.c_str());
            return;
        }
    }

    nucula_console_write("requesting melt quote...\r\n");
    cashu::MeltQuote quote;
    std::optional<int> req_amount = opts.amount > 0
        ? std::optional<int>(opts.amount) : std::nullopt;
    if (!w->request_melt_quote(request, unit, method, quote, req_amount)) {
        nucula_console_write("error: failed to get melt quote\r\n");
        return;
    }

    long long wallet_bal = w->balance_for_unit(quote.unit);
    int total_needed = quote.amount + quote.fee_reserve;
    char amt[48];
    cashu::format_amount(amt, sizeof(amt), quote.amount, quote.unit.c_str());
    console_printf("amount:      %s\r\n", amt);
    cashu::format_amount(amt, sizeof(amt), quote.fee_reserve, quote.unit.c_str());
    console_printf("fee_reserve: %s\r\n", amt);
    cashu::format_amount(amt, sizeof(amt), wallet_bal, quote.unit.c_str());
    console_printf("balance:     %s\r\n", amt);

    if (wallet_bal < total_needed) {
        console_printf("error: insufficient %s balance (%lld < %d)\r\n",
                       quote.unit.c_str(), wallet_bal, total_needed);
        return;
    }

    nucula_console_write("paying...\r\n");
    int change_amount = 0;
    if (!w->melt_tokens(quote, change_amount)) {
        nucula_console_write("error: melt failed\r\n");
        return;
    }

    cashu::format_amount(amt, sizeof(amt), quote.amount, quote.unit.c_str());
    console_printf("paid %s\r\n", amt);
    if (change_amount > 0) {
        cashu::format_amount(amt, sizeof(amt), change_amount, quote.unit.c_str());
        console_printf("change: %s\r\n", amt);
    }
    display_refresh();
}

static void cmd_stickup(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;

    bool any = false;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w || w->proofs().empty()) continue;

        any = true;

        // A token's proofs share one unit, so drain one V4 token per unit.
        // Proofs whose keyset is unknown stay on-device: stamping a guessed
        // unit would make receivers reject or mis-account them.
        std::vector<std::string> units;
        w->collect_units(units);
        for (const auto &u : units) {
            if (u == "?") {
                console_printf("[%d] warning: proofs with unknown keyset "
                               "retained (no unit to stamp)\r\n", i);
                continue;
            }

            std::vector<cashu::Proof> drained;
            for (const auto &p : w->proofs()) {
                const std::string *pu = w->unit_for_proof(p);
                if (pu && *pu == u)
                    drained.push_back(p);
            }
            if (drained.empty()) continue;

            cashu::Token token;
            token.mint = w->mint_url();
            token.unit = u;
            token.proofs = drained;

            std::string serialized = cashu::serialize_token_v4(token);
            if (serialized.empty()) {
                // Without this token string the proofs have no other exit —
                // dropping them here would destroy the funds.
                console_printf("[%d] error: %s token serialization failed, "
                               "not draining\r\n", i, u.c_str());
                continue;
            }

            char amt[48];
            cashu::format_amount(amt, sizeof(amt),
                                 cashu::proofs_sum(drained), u.c_str());
            console_printf("[%d] %s: %s in %d proofs\r\n",
                           i, w->mint_url().c_str(), amt, (int)drained.size());
            nucula_console_write(serialized.c_str());
            nucula_console_write("\r\n");

            if (!w->remove_proofs(drained)) {
                console_printf("[%d] error: failed to persist drain — proofs "
                               "kept on device, token above is a duplicate\r\n", i);
                continue;
            }
            console_printf("[%d] drained %s\r\n", i, u.c_str());
        }
    }

    if (!any)
        nucula_console_write("nothing to drain\r\n");
    else
        display_refresh();
}

// -------------------------------------------------------------------------
// Find My bearer-token outbox
// -------------------------------------------------------------------------

static bool parse_message_id(const char *text, uint32_t &out)
{
    if (!text || !*text) return false;
    char *end = nullptr;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX)
        return false;
    out = (uint32_t)value;
    return true;
}

static void print_find_my_status()
{
    auto status = find_my_nuts::outbox_status();
    console_printf("modem id: %08lX (public)\r\n",
                   (unsigned long)find_my_transport_modem_id());
    console_printf("sender:   %s%s\r\n",
                   status.started ? "started" : "stopped",
                   status.paused ? ", paused" : "");
    if (status.has_active_message)
        console_printf("active:   message %lu%s\r\n",
                       (unsigned long)status.active_message_id,
                       status.paused ? " (armed)" : " (repeating)");
    console_printf("wallet:   %s\r\n",
                   status.reconciled ? "reconciled" : "RECONCILIATION REQUIRED");
    console_printf("outbox:   %u/%u slots used\r\n",
                   (unsigned)status.used_slots, (unsigned)status.capacity);
    if (status.transmitting) {
        unsigned percent = status.total_symbols
            ? (unsigned)(status.current_symbol * 100U / status.total_symbols) : 0;
        console_printf("airing:   message %lu, %u/%u transmissions (%u%%)\r\n",
                       (unsigned long)status.current_message_id,
                       (unsigned)status.current_symbol,
                       (unsigned)status.total_symbols, percent);
    }
    nucula_console_write("warning: this is public, unauthenticated bearer ecash; "
                         "there is no delivery acknowledgement.\r\n");
}

static void handle_dispersion_button(void *)
{
    find_my_nuts::DispersionSelection selection;
    std::string error;
    bool paused = true;
    {
        // All control-plane mutations share the wallet lock with random proof
        // reservation, so a simultaneous console command cannot overtake a
        // physical pause or authorize a second proof.
        wallet_store_guard guard;
        const auto status = find_my_nuts::outbox_status();
        if (!status.initialized || !status.reconciled || !status.started) {
            ESP_LOGW(TAG, "dispersion button ignored: Find My sender not ready");
            return;
        }
        if (status.paused) {
            if (!find_my_nuts::start_continuous_dispersion(selection, error)) {
                ESP_LOGE(TAG, "dispersion button activation failed: %s",
                         error.c_str());
                return;
            }
            paused = false;
        } else if (!find_my_nuts::outbox_pause(error)) {
            ESP_LOGE(TAG, "dispersion button pause failed: %s", error.c_str());
            return;
        }
    }

    if (paused) {
        ESP_LOGW(TAG, "Find My dispersion paused by GPIO%d button",
                 (int)BOARD_DISPERSION_BUTTON_PIN);
    } else {
        ESP_LOGW(TAG, "%s Find My focused session at message %lu "
                 "(%d %s) by GPIO%d button",
                 selection.resumed ? "resumed" : "randomly selected",
                 (unsigned long)selection.message_id,
                 selection.amount, selection.unit.c_str(),
                 (int)BOARD_DISPERSION_BUTTON_PIN);
    }
    display_refresh();
}

static void cmd_findmy(const char *arg)
{
    if (!arg || !*arg || strcmp(arg, "status") == 0) {
        print_find_my_status();
        return;
    }

    if (strcmp(arg, "list") == 0) {
        auto items = find_my_nuts::outbox_items();
        if (items.empty()) {
            nucula_console_write("outbox is empty\r\n");
            return;
        }
        for (const auto &item : items) {
            console_printf("message %-10lu  %4u bytes  %-8s  aired %u pass%s",
                           (unsigned long)item.message_id,
                           (unsigned)item.token_bytes,
                           find_my_nuts::outbox_state_name(item.state),
                           (unsigned)item.passes_completed,
                           item.passes_completed == 1 ? "" : "es");
            if (item.last_error != ESP_OK)
                console_printf("  last=%s", esp_err_to_name(item.last_error));
            nucula_console_write("\r\n");
        }
        return;
    }

    if (strncmp(arg, "arm ", 4) == 0) {
        uint32_t message_id = 0;
        if (!parse_message_id(arg + 4, message_id)) {
            nucula_console_write("usage: findmy arm <message_id>\r\n");
            return;
        }
        std::string error;
        wallet_store_guard guard;
        if (!find_my_nuts::outbox_arm(message_id, error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        console_printf("message %lu armed; sender remains OFF\r\n",
                       (unsigned long)message_id);
        nucula_console_write(
            "detach on battery, then " BOARD_BUTTON_HINT " to repeat this token; "
            "use the same gesture to pause\r\n");
        display_refresh();
        return;
    }

    if (strcmp(arg, "pause") == 0) {
        std::string error;
        wallet_store_guard guard;
        if (!find_my_nuts::outbox_pause(error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        nucula_console_write("Find My sender paused; the same proof will resume "
                             "on the next activation\r\n");
        display_refresh();
        return;
    }

    if (strcmp(arg, "resume") == 0) {
        find_my_nuts::DispersionSelection selection;
        std::string error;
        if (!find_my_nuts::start_continuous_dispersion(selection, error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        nucula_console_write(
            "WARNING: broadcasting public bearer ecash; anyone who reconstructs "
            "it can redeem it first.\r\n");
        console_printf("%s message %lu: %d %s from %s\r\n",
                       selection.resumed ? "resumed" : "randomly selected",
                       (unsigned long)selection.message_id,
                       selection.amount, selection.unit.c_str(),
                       selection.mint.c_str());
        nucula_console_write(
            "focused transmission is active; this same immutable token will "
            "repeat with a new symbol order until paused\r\n");
        display_refresh();
        return;
    }

    if (strncmp(arg, "resend ", 7) == 0) {
        uint32_t message_id = 0;
        if (!parse_message_id(arg + 7, message_id)) {
            nucula_console_write("usage: findmy resend <message_id>\r\n");
            return;
        }
        std::string error;
        wallet_store_guard guard;
        if (!find_my_nuts::outbox_resend(message_id, error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        console_printf("message %lu queued for another full transmission; "
                       "run 'findmy resume' to authorize it\r\n",
                       (unsigned long)message_id);
        return;
    }

    if (strncmp(arg, "token ", 6) == 0) {
        uint32_t message_id = 0;
        if (!parse_message_id(arg + 6, message_id)) {
            nucula_console_write("usage: findmy token <message_id>\r\n");
            return;
        }
        std::string token;
        if (!find_my_nuts::outbox_get_token(message_id, token)) {
            nucula_console_write("error: message ID not found or record corrupt\r\n");
            return;
        }
        nucula_console_write("WARNING: the following string spends bearer ecash:\r\n");
        nucula_console_write(token.c_str());
        nucula_console_write("\r\n");
        return;
    }

    if (strncmp(arg, "forget ", 7) == 0) {
        const char *id_text = arg + 7;
        const char *confirm = strchr(id_text, ' ');
        if (!confirm) {
            nucula_console_write(
                "usage: findmy forget <message_id> CONFIRM\r\n"
                "this permanently deletes the device's serialized bearer token\r\n");
            return;
        }
        std::string id_part(id_text, confirm - id_text);
        while (*confirm == ' ') confirm++;
        uint32_t message_id = 0;
        if (strcmp(confirm, "CONFIRM") != 0
            || !parse_message_id(id_part.c_str(), message_id)) {
            nucula_console_write("usage: findmy forget <message_id> CONFIRM\r\n");
            return;
        }
        std::string error;
        wallet_store_guard guard;
        if (!find_my_nuts::outbox_forget_sent(message_id, error)) {
            console_printf("error: %s\r\n", error.c_str());
            return;
        }
        console_printf("message %lu forgotten; recovery now depends on a copy "
                       "retrieved elsewhere\r\n", (unsigned long)message_id);
        display_refresh();
        return;
    }

    nucula_console_write(
        "usage: findmy [status|list|arm <id>|pause|resume|resend <id>|token <id>|"
        "forget <id> CONFIRM]\r\n");
}

// -------------------------------------------------------------------------
// Seed management (NUT-13)
// -------------------------------------------------------------------------

static void erase_all_wallets()
{
    wallet_store_guard guard;
    wallet_store_remove_all();
}

static void cmd_seed(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0 || strcmp(arg, "show") == 0) {
        std::string mnemonic;
        if (cashu::Wallet::load_mnemonic(mnemonic)) {
            nucula_console_write("WARNING: keep your seed phrase secret!\r\n");
            nucula_console_write(mnemonic.c_str());
            nucula_console_write("\r\n");
        } else {
            nucula_console_write("no seed configured\r\n");
        }
        return;
    }

    if (strcmp(arg, "generate") == 0) {
        char mnemonic[256];
        if (!bip39_generate(mnemonic, sizeof(mnemonic))) {
            nucula_console_write("ERROR: mnemonic generation failed\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(mnemonic, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, mnemonic)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed generated. write down your seed phrase:\r\n\r\n");
        nucula_console_write(mnemonic);
        nucula_console_write("\r\n\r\nall wallet data erased. add mints with 'mint add <url>'\r\n");
        display_refresh();
        return;
    }

    if (strncmp(arg, "restore ", 8) == 0) {
        const char *words = arg + 8;
        while (*words == ' ') words++;

        if (!bip39_validate(words)) {
            nucula_console_write("ERROR: invalid mnemonic (bad checksum or unknown words)\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(words, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, words)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed restored. all wallet data erased.\r\n");
        nucula_console_write("add mints with 'mint add <url>' to begin recovery\r\n");
        display_refresh();
        return;
    }

    if (strcmp(arg, "wipe") == 0) {
        erase_all_wallets();
        cashu::Wallet::erase_seed();
        nucula_console_write("seed and all wallet data erased\r\n");
        display_refresh();
        return;
    }

    nucula_console_write("usage: seed [show|generate|restore <12 words>|wipe]\r\n");
}

static void cmd_reboot(const char *arg)
{
    (void)arg;
    nucula_console_write("rebooting...\r\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

// -------------------------------------------------------------------------
// Telemetry
// -------------------------------------------------------------------------

static void cmd_heap(const char *arg)
{
    (void)arg;
    console_printf("free:          %lu\r\n", (unsigned long)esp_get_free_heap_size());
    console_printf("largest block: %u\r\n",
                   (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    console_printf("min ever free: %lu\r\n",
                   (unsigned long)esp_get_minimum_free_heap_size());
}

static void cmd_tasks(const char *arg)
{
    (void)arg;
    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *st = (TaskStatus_t *)malloc(n * sizeof(TaskStatus_t));
    if (!st) {
        nucula_console_write("error: out of memory\r\n");
        return;
    }
    n = uxTaskGetSystemState(st, n, NULL);
    console_printf("%-16s %4s %10s\r\n", "name", "prio", "stack-min");
    for (UBaseType_t i = 0; i < n; i++)
        console_printf("%-16s %4u %10u\r\n", st[i].pcTaskName,
                       (unsigned)st[i].uxCurrentPriority,
                       (unsigned)st[i].usStackHighWaterMark);
    free(st);
}

static void cmd_log(const char *arg)
{
    esp_log_level_t level;
    if (arg && arg[0] && (arg[1] == '\0' || arg[1] == ' ')) {
        switch (arg[0]) {
            case 'e': level = ESP_LOG_ERROR; break;
            case 'w': level = ESP_LOG_WARN;  break;
            case 'i': level = ESP_LOG_INFO;  break;
            default:  goto usage;
        }
        const char *tag = arg + 1;
        while (*tag == ' ') tag++;
        esp_log_level_set(*tag ? tag : "*", level);
        console_printf("log level '%c' set for %s\r\n", arg[0], *tag ? tag : "*");
        return;
    }
usage:
    nucula_console_write("usage: log <e|w|i> [tag]\r\n");
}

static void cmd_bench(const char *arg)
{
    if (arg && strncmp(arg, "bls", 3) == 0) {
        nucula_console_write("benchmarking BLS12-381 primitives (slow on the portable path)...\r\n");
        crypto_bls_run_benchmark();
    } else {
        nucula_console_write("benchmarking crypto primitives...\r\n");
        crypto_run_benchmark(wallet_store_ctx());
    }
    nucula_console_write("done (results logged at info level)\r\n");
}

static void cmd_selftest(const char *arg)
{
    (void)arg;
    nucula_console_write("running self-tests (details logged at info level)...\r\n");
    bool ok = crypto_run_tests(wallet_store_ctx()) != 0;
    if (!crypto_bls_run_tests())
        ok = false;
    if (!cashu::keyset_run_tests())
        ok = false;
    if (!cashu::unit_run_tests())
        ok = false;
    if (!cashu::cashu_json_run_tests())
        ok = false;
    if (!cashu::cashu_cbor_run_tests())
        ok = false;
    if (!cashu::proof_distribution_run_tests())
        ok = false;
    if (!find_my_nuts::find_my_policy_run_tests())
        ok = false;
    if (!find_my_schedule_run_tests())
        ok = false;
    console_printf("self-tests %s\r\n", ok ? "PASSED" : "FAILED");
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "find-my-nuts cashu wallet");

    // NVS backs the wallet itself (proofs, seed, keysets) — bring it up
    // first and independently of WiFi.
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err != ESP_OK) {
        // NVS is the wallet: an automatic "repair" erase would destroy the
        // seed, proofs, and the only recovery copies in the Find My outbox.
        // Fail closed and leave the flash untouched for operator recovery.
        ESP_LOGE(TAG, "NVS init failed: %s; refusing automatic wallet erase",
                 esp_err_to_name(nvs_err));
        ESP_LOGE(TAG, "recover/backup flash, or explicitly erase it before reboot");
    }

    // Bring up the selected board's display before Wi-Fi's
    // initial connection wait so boot progress is immediately visible.
    display_init();
    if (board_tdisplay_power_init() != ESP_OK)
        ESP_LOGW(TAG, "power indicator unavailable");
    display_clear();
    display_text((LCD_W - display_text_width("FIND MY NUTS", 1)) / 2,
                 LCD_H / 2 - 4, "FIND MY NUTS", 1);
    display_update();

    if (nvs_err != ESP_OK) {
        display_clear();
        display_text(2, 8, "NVS ERROR", 1);
        display_text(2, 24, "WALLET NOT ERASED", 1);
        display_text(2, 40, "CHECK SERIAL", 1);
        display_update();
        return;
    }

    // Reserve the UART rings, line buffer, command vector and 24 KiB command
    // stack before Wi-Fi/BLE/TLS consume heap. The console task may echo input
    // during boot, but console_set_ready() gates every command handler until
    // wallet, outbox, seed and keyset initialization are complete.
    int console_err = console_init(NULL);
    if (console_err == 0) {
        console_register_cmd("status",  cmd_status,  "show system and wallet status");
        console_register_cmd("balance", cmd_balance,  "show wallet balance per unit");
        console_register_cmd("unit",    cmd_unit,     "unit [<name>] — show/set default unit");
        console_register_cmd("receive", cmd_receive,  "receive a cashuA token");
        console_register_cmd("mint",    cmd_mint,     "mint [list|add <url-or-host>|remove <idx>|info]");
        console_register_cmd("invoice", cmd_invoice,  "invoice <amount> [u=|m=|w=]");
        console_register_cmd("claim",   cmd_claim,    "claim <id> [d=1xN]");
        console_register_cmd("melt",    cmd_melt,     "melt <request> [u=|m=|a=|w=]");
        console_register_cmd("stickup", cmd_stickup,  "drain wallet into v4 tokens");
        console_register_cmd("findmy",  cmd_findmy,   "Find My outbox/status controls");
        console_register_cmd("seed",    cmd_seed,     "seed [show|generate|restore|wipe]");
        console_register_cmd("reboot",  cmd_reboot,   "restart the device");
        console_register_cmd("heap",    cmd_heap,     "show heap usage");
        console_register_cmd("tasks",   cmd_tasks,    "show task stack high-water marks");
        console_register_cmd("log",     cmd_log,      "log <e|w|i> [tag] — set log level");
        console_register_cmd("bench",   cmd_bench,    "bench [bls] — benchmark crypto primitives");
        console_register_cmd("selftest", cmd_selftest, "run crypto/keyset self-tests");
        console_err = console_start();
    }
    if (console_err != 0)
        ESP_LOGE(TAG, "console init/start failed: %d", console_err);

    http_init();

    if (wifi_init() != ESP_OK)
        ESP_LOGE(TAG, "wifi failed, continuing offline");

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }
    {
        unsigned char rand32[32];
        esp_fill_random(rand32, sizeof(rand32));
        if (!secp256k1_context_randomize(ctx, rand32))
            ESP_LOGW(TAG, "secp256k1 context randomize failed");
    }

    if (!wallet_store_init(ctx)) {
        ESP_LOGE(TAG, "wallet store init failed");
        return;
    }

    std::string outbox_error;
    bool outbox_ready = find_my_nuts::outbox_init(outbox_error);
    if (!outbox_ready) {
        ESP_LOGE(TAG, "Find My outbox init failed: %s", outbox_error.c_str());
    } else {
        find_my_nuts::ReconcileResult reconcile;
        outbox_error.clear();
        if (!find_my_nuts::reconcile_outbox_with_wallets(reconcile, outbox_error)) {
            ESP_LOGE(TAG, "Find My outbox reconciliation needs attention: %s",
                     outbox_error.c_str());
        }
        if (reconcile.proofs_removed > 0) {
            ESP_LOGW(TAG, "reconciled %u Find My proof(s) out of live wallet state",
                     (unsigned)reconcile.proofs_removed);
        }
    }

#if CONFIG_NUCULA_SELFTEST_ON_BOOT
    crypto_run_tests(ctx);
    if (!crypto_bls_run_tests())
        ESP_LOGE(TAG, "BLS crypto self-test FAILED");
    if (!cashu::keyset_run_tests())
        ESP_LOGE(TAG, "keyset id derivation self-test FAILED");
    if (!cashu::unit_run_tests())
        ESP_LOGE(TAG, "unit formatter self-test FAILED");
    if (!cashu::cashu_json_run_tests())
        ESP_LOGE(TAG, "quote/mint-info JSON self-test FAILED");
    if (!cashu::cashu_cbor_run_tests())
        ESP_LOGE(TAG, "v4 token CBOR self-test FAILED");
    if (!cashu::proof_distribution_run_tests())
        ESP_LOGE(TAG, "proof distribution self-test FAILED");
    if (!find_my_nuts::find_my_policy_run_tests())
        ESP_LOGE(TAG, "Find My policy self-test FAILED");
    if (!find_my_schedule_run_tests())
        ESP_LOGE(TAG, "Find My schedule self-test FAILED");
#endif

    cashu::Wallet::load_seed();
    cashu::Wallet::ensure_p2pk_keypair(wallet_store_ctx());
    // Warm the cache before the UI task exists so later reads
    // from other tasks never hit the lazy NVS load.
    cashu::Wallet::default_unit();

    if (wifi_is_connected()) {
        for (int i = 0; i < MAX_MINTS; i++) {
            auto *w = wallet_store_get(i);
            if (!w) continue;
            // A transactionally-added mint already has a validated, durable
            // keyset. Refreshing it on every boot delayed console readiness by
            // tens of seconds and fragmented heap before the first command.
            if (w->keysets().empty() && !w->load_keysets())
                ESP_LOGW(TAG, "failed to refresh keysets for [%d]", i);
        }
    }

    // Drain task: while WiFi is connected, walk each wallet's pending queue
    // and try to swap the stashed offline-receive tokens. We can't drain just
    // once on the rising edge: DNS/routing is often not usable for the first
    // few seconds after GOT_IP, and a link that stays up never produces
    // another edge. So once connected we retry with an exponential backoff
    // until everything is redeemed (or the link drops), then re-arm on the
    // next reconnect. 20 KB stack: draining v3 tokens runs the chunked
    // multi-miller pairing batch in receive() (console measured ~16.5 KB
    // peak on the same verification frames).
    EventGroupHandle_t wifi_events = wifi_get_event_group();
    BaseType_t drain_task_created = pdFAIL;
    // This T-Display variant has no NFC producer for new pending tokens. Only
    // allocate the large BLS-capable recovery stack when legacy NVS actually
    // contains work; otherwise it permanently wastes ~20 KB of internal RAM.
    const bool pending_recovery_needed = wallet_store_total_pending() > 0;
    if (wifi_events && pending_recovery_needed) {
        drain_task_created = xTaskCreate([](void *arg) {
        EventGroupHandle_t eg = static_cast<EventGroupHandle_t>(arg);
        for (;;) {
            xEventGroupWaitBits(eg, WIFI_CONNECTED_BIT,
                                pdFALSE, pdTRUE, portMAX_DELAY);
            /* Settle: give the IP stack a moment before the first HTTP. */
            vTaskDelay(pdMS_TO_TICKS(2000));

            TickType_t backoff = pdMS_TO_TICKS(5000);
            const TickType_t backoff_max = pdMS_TO_TICKS(60000);
            while (xEventGroupGetBits(eg) & WIFI_CONNECTED_BIT) {
                if (wallet_store_total_pending() == 0) {
                    ESP_LOGI(TAG, "pending-token recovery complete; releasing task");
                    vTaskDelete(NULL);
                    return;
                }

                int total_ok = 0, total_fail = 0;
                for (int i = 0; i < MAX_MINTS; i++) {
                    // Per-slot guard: released between slots so console
                    // commands can interleave with a long drain pass.
                    wallet_store_guard guard;
                    auto *w = wallet_store_get(i);
                    if (!w || w->pending_count() == 0) continue;
                    int ok = 0, fail = 0;
                    w->drain_pending_tokens(ok, fail);
                    total_ok += ok;
                    total_fail += fail;
                }
                if (total_ok || total_fail) {
                    ESP_LOGI(TAG, "drain: %d ok, %d failed across all slots",
                             total_ok, total_fail);
                    display_refresh();
                }

                if (total_ok > 0) {
                    /* Made progress; retry promptly for the rest. */
                    backoff = pdMS_TO_TICKS(5000);
                    vTaskDelay(backoff);
                } else {
                    /* No progress (DNS not ready / mint down). Back off so we
                     * don't hammer the network, capped at backoff_max. */
                    vTaskDelay(backoff);
                    if (backoff < backoff_max)
                        backoff = backoff * 2 < backoff_max ? backoff * 2
                                                            : backoff_max;
                }
            }

            /* Drained, or the link dropped. Wait until the bit clears so the
             * next reconnect re-arms us. */
            while (xEventGroupGetBits(eg) & WIFI_CONNECTED_BIT)
                vTaskDelay(pdMS_TO_TICKS(5000));
        }
        }, "wifi_drain", 20480, wifi_events, 4, NULL);
    }
    if (pending_recovery_needed && drain_task_created != pdPASS)
        ESP_LOGE(TAG, "Wi-Fi pending-token drain task unavailable");

    display_refresh();
    if (xTaskCreate(display_ui_task, "display_ui", 3072, NULL, 2, NULL)
        != pdPASS) {
        ESP_LOGE(TAG, "display UI task unavailable");
    }

    bool outbox_started = false;
    if (outbox_ready) {
        outbox_error.clear();
        if (!find_my_nuts::outbox_start(outbox_error)) {
            ESP_LOGE(TAG, "Find My sender start failed: %s", outbox_error.c_str());
        } else {
            outbox_started = true;
        }
    }

    // Register the board's explicit sender gesture after durable state and
    // transport initialization. Wi-Fi events never authorize transmission.
    if (outbox_started)
        board_tdisplay_set_dispersion_handler(handle_dispersion_button, nullptr);

    // All long-lived task stacks and BLE state are now reserved too, so a
    // console TLS/crypto command cannot starve the final boot allocations.
    // This runs in the offline path; Wi-Fi is not a console prerequisite.
    console_set_ready();
}
