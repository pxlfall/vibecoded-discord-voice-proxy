#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace proxydns {
enum class Status { ok, not_found, malformed, server_error };
struct Answer {
    Status status = Status::malformed;
    std::vector<std::array<uint8_t, 4>> addresses;
    std::string canonical;
    uint32_t ttl = 0;
};
std::vector<uint8_t> MakeQuery(const std::string& hostname);
Answer ParseAnswer(const std::vector<uint8_t>& packet, const std::string& hostname);
}
