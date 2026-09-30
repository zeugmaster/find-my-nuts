#include "proof_distribution.hpp"

#include <cstdint>
#include <cstdio>
#include <limits>

#include <esp_log.h>

#define TAG "proof_dist"

namespace cashu {
namespace {

bool parse_positive_decimal(const std::string& text,
                            uint64_t limit,
                            uint64_t& value,
                            const char* field,
                            std::string& error)
{
    if (text.empty()) {
        error = std::string(field) + " is missing";
        return false;
    }

    uint64_t parsed = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            error = std::string(field) + " must be a positive integer: " + text;
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (digit > limit || parsed > (limit - digit) / 10) {
            error = std::string(field) + " is too large: " + text;
            return false;
        }
        parsed = parsed * 10 + digit;
    }

    if (parsed == 0) {
        error = std::string(field) + " must be greater than zero";
        return false;
    }

    value = parsed;
    return true;
}

std::string count_error(size_t max_proof_count)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "too many proofs (maximum %llu)",
             static_cast<unsigned long long>(max_proof_count));
    return std::string(buf);
}

std::string total_error(int64_t actual, int claimable)
{
    char buf[96];
    snprintf(buf, sizeof(buf),
             "distribution totals %lld; claimable amount is %d",
             static_cast<long long>(actual), claimable);
    return std::string(buf);
}

} // namespace

bool parse_proof_distribution(const std::string& option,
                              int claimable_amount,
                              size_t max_proof_count,
                              std::vector<int>& amounts_out,
                              std::string& error_out)
{
    amounts_out.clear();
    error_out.clear();

    if (claimable_amount <= 0) {
        error_out = "claimable amount must be greater than zero";
        return false;
    }
    if (max_proof_count == 0) {
        error_out = "proof limit must be greater than zero";
        return false;
    }
    if (option.compare(0, 2, "d=") != 0) {
        error_out = "distribution must start with d=";
        return false;
    }

    const std::string spec = option.substr(2);
    if (spec.empty()) {
        error_out = "distribution is empty";
        return false;
    }

    // Build into a temporary vector so callers never observe a partial parse.
    std::vector<int> parsed_amounts;
    int64_t total = 0;
    size_t term_start = 0;

    while (term_start <= spec.size()) {
        const size_t separator = spec.find('-', term_start);
        const size_t term_end = separator == std::string::npos
                              ? spec.size() : separator;
        const std::string term = spec.substr(term_start, term_end - term_start);
        if (term.empty()) {
            error_out = "distribution contains an empty term";
            return false;
        }

        const size_t x = term.find('x');
        if (x != std::string::npos && term.find('x', x + 1) != std::string::npos) {
            error_out = "repeat must use amountxcount: " + term;
            return false;
        }

        const std::string amount_text = term.substr(0, x);
        const std::string count_text = x == std::string::npos
                                     ? std::string() : term.substr(x + 1);

        uint64_t amount = 0;
        if (!parse_positive_decimal(amount_text,
                                    static_cast<uint64_t>(std::numeric_limits<int>::max()),
                                    amount, "amount", error_out)) {
            return false;
        }

        uint64_t count = 1;
        if (x != std::string::npos) {
            if (!parse_positive_decimal(count_text,
                                        std::numeric_limits<uint64_t>::max(), count,
                                        "repeat count", error_out)) {
                return false;
            }
        }

        if (count > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
            static_cast<size_t>(count) >
                max_proof_count - parsed_amounts.size()) {
            error_out = count_error(max_proof_count);
            return false;
        }

        const uint64_t total_room = static_cast<uint64_t>(
            std::numeric_limits<int64_t>::max() - total);
        if (amount > total_room / count) {
            error_out = "distribution total is too large";
            return false;
        }
        total += static_cast<int64_t>(amount * count);

        // Claimable amounts are `int`; once this total is exceeded, no later
        // positive term can restore equality. Report the same useful mismatch
        // as a completed but incorrect distribution without expanding a huge
        // repeat unnecessarily.
        if (total > claimable_amount) {
            error_out = total_error(total, claimable_amount);
            return false;
        }

        parsed_amounts.insert(parsed_amounts.end(), static_cast<size_t>(count),
                              static_cast<int>(amount));

        if (separator == std::string::npos)
            break;
        term_start = separator + 1;
    }

    if (total != claimable_amount) {
        error_out = total_error(total, claimable_amount);
        return false;
    }

    amounts_out.swap(parsed_amounts);
    return true;
}

bool proof_distribution_run_tests()
{
    bool ok = true;

    auto expect_ok = [&](const char* name, const char* input, int claimable,
                         size_t limit, const std::vector<int>& expected) {
        std::vector<int> actual{99};
        std::string error("stale");
        const bool parsed = parse_proof_distribution(input, claimable, limit,
                                                     actual, error);
        if (!parsed || actual != expected || !error.empty()) {
            ESP_LOGE(TAG, "%s FAIL: parsed=%d count=%d error=\"%s\"",
                     name, parsed, static_cast<int>(actual.size()), error.c_str());
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok", name);
        }
    };

    auto expect_fail = [&](const char* name, const char* input, int claimable,
                           size_t limit) {
        std::vector<int> actual{99};
        std::string error;
        const bool parsed = parse_proof_distribution(input, claimable, limit,
                                                     actual, error);
        if (parsed || !actual.empty() || error.empty()) {
            ESP_LOGE(TAG, "%s FAIL: parsed=%d count=%d error=\"%s\"",
                     name, parsed, static_cast<int>(actual.size()), error.c_str());
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok (%s)", name, error.c_str());
        }
    };

    expect_ok("explicit", "d=1-1-1-1-1", 5, 8, {1, 1, 1, 1, 1});
    expect_ok("repeat", "d=1x5", 5, 5, {1, 1, 1, 1, 1});
    expect_ok("mixed", "d=1x2-2-4x2", 12, 8, {1, 1, 2, 4, 4});
    expect_ok("int max", "d=2147483647", std::numeric_limits<int>::max(),
              1, {std::numeric_limits<int>::max()});

    expect_fail("missing prefix", "1x5", 5, 8);
    expect_fail("empty", "d=", 5, 8);
    expect_fail("empty term", "d=1--1", 2, 8);
    expect_fail("trailing term", "d=1-", 1, 8);
    expect_fail("zero amount", "d=0", 1, 8);
    expect_fail("zero repeat", "d=1x0", 1, 8);
    expect_fail("missing repeat", "d=1x", 1, 8);
    expect_fail("bad character", "d=1-a", 2, 8);
    expect_fail("multiple x", "d=1x2x3", 6, 8);
    expect_fail("amount overflow", "d=2147483648", 1, 8);
    expect_fail("repeat overflow", "d=1x18446744073709551616", 1, 8);
    expect_fail("proof cap", "d=1x6", 6, 5);
    expect_fail("sum short", "d=1-1", 3, 8);
    expect_fail("sum over", "d=2-2", 3, 8);
    expect_fail("zero cap", "d=1", 1, 0);
    expect_fail("zero claimable", "d=1", 0, 1);

    return ok;
}

} // namespace cashu
