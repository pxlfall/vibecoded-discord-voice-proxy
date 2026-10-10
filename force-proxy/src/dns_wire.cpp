#include "dns_wire.h"
#include <algorithm>
#include <cctype>
#include <map>
#include <limits>

namespace proxydns {
namespace {
std::string Normalize(std::string name) {
    if (!name.empty() && name.back() == '.') name.pop_back();
    for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return name;
}
uint16_t U16(const std::vector<uint8_t>& p, size_t n) {
    return static_cast<uint16_t>((p[n] << 8) | p[n + 1]);
}
uint32_t U32(const std::vector<uint8_t>& p, size_t n) {
    return (uint32_t(p[n]) << 24) | (uint32_t(p[n + 1]) << 16) |
           (uint32_t(p[n + 2]) << 8) | p[n + 3];
}
bool Name(const std::vector<uint8_t>& p, size_t& offset, std::string& out) {
    size_t cursor = offset;
    bool jumped = false;
    out.clear();
    for (unsigned steps = 0; steps < 128; ++steps) {
        if (cursor >= p.size()) return false;
        const unsigned length = p[cursor++];
        if ((length & 0xc0) == 0xc0) {
            if (cursor >= p.size()) return false;
            const size_t target = ((length & 0x3f) << 8) | p[cursor++];
            if (!jumped) offset = cursor;
            jumped = true;
            cursor = target;
            continue;
        }
        if (length & 0xc0) return false;
        if (!length) {
            if (!jumped) offset = cursor;
            out = Normalize(out);
            return true;
        }
        if (cursor + length > p.size()) return false;
        if (!out.empty()) out += '.';
        for (size_t i = 0; i < length; ++i) {
            const auto c = p[cursor++];
            if (c <= 32 || c >= 127 || c == '.') return false;
            out += static_cast<char>(c);
        }
        if (out.size() > 253) return false;
    }
    return false; // Includes cyclic compression pointers.
}
}
std::vector<uint8_t> MakeQuery(const std::string& hostname) {
    const auto name = Normalize(hostname);
    if (name.empty() || name.size() > 253) return {};
    // DoH does not need a randomized transaction ID; use zero (RFC 8484).
    std::vector<uint8_t> p = {0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    size_t start = 0;
    while (start < name.size()) {
        const auto end = name.find('.', start);
        const auto length = (end == std::string::npos ? name.size() : end) - start;
        if (!length || length > 63) return {};
        p.push_back(static_cast<uint8_t>(length));
        for (size_t i = start; i < start + length; ++i) {
            const auto c = static_cast<unsigned char>(name[i]);
            if (c <= 32 || c >= 127) return {};
            p.push_back(c);
        }
        start += length + 1;
    }
    p.insert(p.end(), {0, 0, 1, 0, 1}); // A, IN
    return p;
}
Answer ParseAnswer(const std::vector<uint8_t>& p, const std::string& hostname) {
    Answer result;
    if (p.size() < 12 || p.size() > 65535 || U16(p, 0) != 0 || U16(p, 4) != 1) return result;
    const auto flags = U16(p, 2);
    if (!(flags & 0x8000) || (flags & 0x7800) || (flags & 0x0200)) return result;
    size_t offset = 12;
    std::string question;
    if (!Name(p, offset, question) || question != Normalize(hostname) ||
        offset + 4 > p.size() || U16(p, offset) != 1 || U16(p, offset + 2) != 1) return result;
    offset += 4;
    const auto rcode = flags & 15;
    if (rcode) {
        result.status = rcode == 3 ? Status::not_found : Status::server_error;
        return result;
    }
    struct Record { std::string owner; std::array<uint8_t, 4> ip; uint32_t ttl; };
    std::vector<Record> records;
    std::map<std::string, std::pair<std::string, uint32_t>> aliases;
    const auto count = U16(p, 6);
    if (count > 256) return result;
    for (unsigned i = 0; i < count; ++i) {
        std::string owner;
        if (!Name(p, offset, owner) || offset + 10 > p.size()) return result;
        const auto type = U16(p, offset), klass = U16(p, offset + 2);
        const auto ttl = U32(p, offset + 4);
        const auto length = U16(p, offset + 8);
        offset += 10;
        if (offset + length > p.size()) return result;
        if (klass == 1 && type == 1) {
            if (length != 4) return result;
            records.push_back({owner, {p[offset], p[offset + 1], p[offset + 2], p[offset + 3]}, ttl});
        } else if (klass == 1 && type == 5) {
            size_t aliasOffset = offset;
            std::string target;
            if (!Name(p, aliasOffset, target) || aliasOffset != offset + length || target.empty()) return result;
            aliases[owner] = {target, ttl};
        }
        offset += length;
    }
    auto canonical = Normalize(hostname);
    uint32_t ttl = std::numeric_limits<uint32_t>::max();
    for (unsigned i = 0; aliases.count(canonical); ++i) {
        if (i == 16) return result;
        const auto& alias = aliases.at(canonical);
        ttl = std::min(ttl, alias.second);
        canonical = alias.first;
    }
    for (const auto& record : records) {
        if (record.owner != canonical) continue;
        if (std::find(result.addresses.begin(), result.addresses.end(), record.ip) == result.addresses.end())
            result.addresses.push_back(record.ip);
        ttl = std::min(ttl, record.ttl);
    }
    result.canonical = canonical;
    result.ttl = result.addresses.empty() ? 0 : std::min(ttl, uint32_t(300));
    result.status = result.addresses.empty() ? Status::not_found : Status::ok;
    return result;
}
}
