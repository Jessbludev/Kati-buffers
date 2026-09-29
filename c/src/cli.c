#include "kati.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void) {
    fputs("kati — .pbr tool (C host)\n\n"
          "Usage:\n"
          "  kati version\n"
          "  kati inspect <file.pbr>\n"
          "  kati schema-hash <file.pbr>\n",
          stderr);
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = 0;
    *len = got;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }
    if (strcmp(argv[1], "help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(argv[1], "version") == 0) {
        printf("kati %d (C ABI)\n", KATI_VERSION);
        return 0;
    }
    if (argc < 3) {
        usage();
        return 1;
    }
    size_t len = 0;
    unsigned char *data = read_file(argv[2], &len);
    if (!data) {
        fprintf(stderr, "cannot read %s\n", argv[2]);
        return 1;
    }
    if (strcmp(argv[1], "inspect") == 0) {
        kati_header h;
        kati_status st = kati_decode_header(data, len, &h);
        if (st) {
            fprintf(stderr, "inspect: %s\n", kati_status_str(st));
            free(data);
            return 1;
        }
        printf("format: PBR v%d\nflags: 0x%02x\nschema_hash: 0x%016llx\npayload_len: %llu\nheader_len: %zu\n",
               KATI_VERSION,
               h.flags,
               (unsigned long long)h.schema_hash,
               (unsigned long long)h.payload_len,
               h.header_len);
        free(data);
        return 0;
    }
    if (strcmp(argv[1], "schema-hash") == 0) {
        kati_schema s;
        kati_status st = kati_parse_schema((const char *)data, &s);
        if (st) {
            fprintf(stderr, "schema-hash: %s\n", kati_status_str(st));
            free(data);
            return 1;
        }
        printf("schema: %s\nhash: 0x%016llx\nfields: %zu\nstrict: %s\n",
               s.name,
               (unsigned long long)s.schema_hash,
               s.field_count,
               s.strict ? "true" : "false");
        free(data);
        return 0;
    }
    usage();
    free(data);
    return 1;
}
