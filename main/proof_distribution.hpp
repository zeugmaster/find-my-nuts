#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace cashu {

// Parse an exact mint-output distribution option. `option` must use the
// console form d=<spec>, where spec is a hyphen-separated list of either
// denominations or compact amountxcount repeats:
//
//   d=1-1-2-4
//   d=1x5
//   d=1x3-2-4x2
//
// Amounts and repeat counts are strict positive decimal integers. On success,
// `amounts_out` contains the expanded denomination list and its sum is exactly
// `claimable_amount`. On failure, `amounts_out` is empty and `error_out` holds
// a short message suitable for printing directly to the console.
bool parse_proof_distribution(const std::string& option,
                              int claimable_amount,
                              size_t max_proof_count,
                              std::vector<int>& amounts_out,
                              std::string& error_out);

// Parser contract tests for the on-device `selftest` command.
bool proof_distribution_run_tests();

} // namespace cashu
