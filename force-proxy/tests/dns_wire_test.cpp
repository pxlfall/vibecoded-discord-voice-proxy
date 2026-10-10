#include "dns_wire.h"
#include <iostream>
#include <stdexcept>

using namespace proxydns;
void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::vector<uint8_t> Reply() {
    auto p = MakeQuery("discord.com");
    p[2] = 0x81; p[3] = 0x80; p[7] = 1;
    p.insert(p.end(), {0xc0,12, 0,1, 0,1, 0,0,0,60, 0,4, 162,159,138,232});
    return p;
}
int main() {
    try {
        const auto query = MakeQuery("discord.com");
        Check(query.size() == 29, "Query wire size");
        Check(MakeQuery("a..com").empty(), "Reject empty label");
        Check(MakeQuery(std::string(64,'x') + ".com").empty(), "Reject long label");
        auto p = Reply();
        auto answer = ParseAnswer(p, "DISCORD.COM.");
        Check(answer.status == Status::ok && answer.addresses.size() == 1 && answer.ttl == 60, "Decode compressed A answer");
        Check(answer.addresses[0] == std::array<uint8_t,4>{162,159,138,232}, "Correct address bytes");
        Check(ParseAnswer(p,"other.com").status == Status::malformed, "Reject mismatched question");
        for (size_t length = 0; length < p.size(); ++length)
            Check(ParseAnswer(std::vector<uint8_t>(p.begin(),p.begin()+length),"discord.com").status == Status::malformed, "Reject truncated packets");
        p[0] = 1;
        Check(ParseAnswer(p,"discord.com").status == Status::malformed, "Reject transaction mismatch");
        p = Reply(); p[2] |= 2;
        Check(ParseAnswer(p,"discord.com").status == Status::malformed, "Reject TC flag");
        p = query; p[2] = 0x81; p[3] = 0x83;
        Check(ParseAnswer(p,"discord.com").status == Status::not_found, "NXDOMAIN fails closed");
        p[3] = 0x82;
        Check(ParseAnswer(p,"discord.com").status == Status::server_error, "SERVFAIL is transient");
        p = Reply(); p[29] = 0xc0; p[30] = 29;
        Check(ParseAnswer(p,"discord.com").status == Status::malformed, "Reject compression loop");
        p = Reply(); p[37] = 0xff; p[38] = 0xff;
        Check(ParseAnswer(p,"discord.com").ttl == 300, "Bound cache TTL");
        p = query; p[2] = 0x81; p[3] = 0x80; p[7] = 2;
        p.insert(p.end(), {0xc0,12, 0,5, 0,1, 0,0,0,20, 0,8, 5,'a','l','i','a','s',0xc0,20});
        const auto alias = p.size() - 8;
        p.insert(p.end(), {0xc0,static_cast<uint8_t>(alias), 0,1, 0,1, 0,0,0,60, 0,4, 1,2,3,4});
        answer = ParseAnswer(p,"discord.com");
        Check(answer.status == Status::ok && answer.canonical == "alias.com" && answer.ttl == 20, "CNAME chain and TTL");
        std::cout << "DNS parser tests passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
