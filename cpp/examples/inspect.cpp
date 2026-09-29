#include "kati.hpp"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fputs("usage: kati-cpp <file.pbr>\n", stderr);
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<char> raw{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    auto bytes = std::span<const std::byte>(reinterpret_cast<const std::byte *>(raw.data()), raw.size());
    auto v = kati::view::open(bytes);
    if (!v) {
        std::fprintf(stderr, "inspect: %s\n", kati::to_string(v.st));
        return 1;
    }
    const auto &h = v.value.hdr();
    std::printf("schema_hash: 0x%016llx\npayload_len: %llu\nheader_len: %zu\n",
                static_cast<unsigned long long>(h.schema_hash), static_cast<unsigned long long>(h.payload_len),
                h.header_len);
    auto cur = v.value.fields();
    while (!cur.done()) {
        auto field = cur.field();
        if (!field) break;
        std::printf("  field %u wire %u\n", field.value.field_id, static_cast<unsigned>(field.value.type));
        cur.skip(field.value.type);
    }
    return 0;
}
