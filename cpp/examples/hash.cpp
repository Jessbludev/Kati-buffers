#include "kati.hpp"

#include <cstdio>

static constexpr char kAppConfig[] =
    "@strict\n"
    "config AppConfig {\n"
    "    name: string @required\n"
    "    version: u16\n"
    "    debug: bool = false\n"
    "    endpoints: array[string] @max(32)\n"
    "    limits: map[string,u32]\n"
    "    payload: bytes @compress(zstd)\n"
    "}\n";

int main() {
    auto schema = kati::parse_schema(kAppConfig);
    if (!schema) {
        std::fprintf(stderr, "parse: %s\n", kati::to_string(schema.st));
        return 1;
    }
    std::printf("schema: %s\nhash: 0x%016llx\nfields: %zu\n", schema.value.name,
                static_cast<unsigned long long>(schema.value.schema_hash), schema.value.field_count);
    if (schema.value.schema_hash != 0x3d742323fdeca80bull) return 1;

    std::byte buf[32];
    kati::sink s{std::span<std::byte>(buf)};
    const char payload[] = "hi";
    auto st = s.mux(7, kati::mux_bits::syn | kati::mux_bits::ack, 42,
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload), 2));
    if (st != kati::status::ok) return 1;
    kati::cursor c{std::span<const std::byte>(buf, s.pos())};
    auto frame = c.mux();
    if (!frame || frame.value.chid != 7 || frame.value.seq != 42) return 1;
    std::puts("ok");
    return 0;
}
