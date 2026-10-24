#ifndef GLASSY_PROTO_TESTS_VECTORS_H_
#define GLASSY_PROTO_TESTS_VECTORS_H_

#include <cstdint>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Loads vectors/<file> (written by the Rust generators) from GLASSY_VECTORS_DIR.
nlohmann::json load_vectors(std::string_view file);
// Decodes lowercase/uppercase hex; aborts the test binary on malformed input.
std::vector<uint8_t> hex(std::string_view s);
std::string to_hex(std::span<const uint8_t> bytes);
// Parses a `label: hex` fixture (with `#` comments) from GLASSY_FIXTURES_DIR, in file order.
std::vector<std::pair<std::string, std::vector<uint8_t>>> load_fixture(std::string_view file);

#endif  // GLASSY_PROTO_TESTS_VECTORS_H_
