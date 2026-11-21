/*
 * Host test for the extended ic-syms geometry parser (ic_geo_load).
 *
 * Build & run:
 *   cc -Wall -Wextra -DIC_SYMS_HAVE_ZLIB tests/geo_test.c ic_syms.c -lz -o geo_test
 *   ./geo_test <tests/ic-syms-geo.txt>
 *
 * The fixture path may be overridden with argv[1].
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ic_syms.h"

static int failures;

static void expect(const char *what, unsigned long long got,
                   unsigned long long want)
{
    if (got != want) {
        printf("FAIL %s: got %#llx want %#llx\n", what, got, want);
        failures++;
    }
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tests/ic-syms-geo.txt";
    struct ic_geo geo;
    int keys;

    keys = ic_geo_load(path, &geo);
    if (keys < 0) {
        printf("FAIL cannot open %s\n", path);
        return 1;
    }
    expect("keys", (unsigned long long)keys, 19);
    expect("essential", (unsigned long long)geo.essential,
           (unsigned long long)IC_GEOM_ESSENTIAL);
    expect("timer_alloc", geo.timer_alloc, 0x108);
    expect("cred_req", geo.cred_req, 0xb8);
    expect("cred_alloc", geo.cred_alloc, 0xc0);
    expect("task_alloc_bytes", geo.task_alloc_bytes, 0x1500);
    expect("task_cred", geo.task_cred, 0x838);
    expect("cred_uid", geo.cred_uid, 0x8);
    expect("cap_inh", geo.cap_inh, 0x2c);
    expect("cap_amb", geo.cap_amb, 0x4c);
    expect("cred_group_info", geo.cred_group_info, 0x98);
    expect("tp_funcs", geo.tp_funcs, 0x40);
    expect("timer_node_off", geo.timer_node_off, 0x78);
    expect("fullcap", geo.fullcap, 0x1ffffffffffULL);
    if (strcmp(geo.build, "6.1.145-android14-11-maybe-dirty")) {
        printf("FAIL build banner: got %s\n", geo.build);
        failures++;
    }

    /* A symbols-only table (old format) must parse as zero geometry and
     * keep the banner. */
    {
        FILE *f = fopen("/tmp/ic-syms-legacy.txt", "w");
        if (!f) return 1;
        fputs("# ic-timer symbol table\n", f);
        fputs("# build=6.1.157-android14-11-gb3d4cdadf339\n", f);
        fputs("__tracepoint_sys_exit=0xffffffc00a1b1da0\n", f);
        fputs("init_cred=0xffffffc00a031aa8\n", f);
        fclose(f);
        memset(&geo, 0, sizeof(geo));
        keys = ic_geo_load("/tmp/ic-syms-legacy.txt", &geo);
        expect("legacy keys", (unsigned long long)keys, 0);
        expect("legacy essential", (unsigned long long)geo.essential, 0);
        if (strcmp(geo.build, "6.1.157-android14-11-gb3d4cdadf339")) {
            printf("FAIL legacy banner: got %s\n", geo.build);
            failures++;
        }
    }

    /* Malformed lines are skipped, unknown keys ignored, zero values
     * rejected (0 means "absent"). */
    {
        FILE *f = fopen("/tmp/ic-syms-bad.txt", "w");
        if (!f) return 1;
        fputs("off.timer_alloc=zzz\n", f);
        fputs("off.unknown_key=0x10\n", f);
        fputs("off.cred_req=0x0\n", f);
        fputs("off.cred_req=0xb0\n", f);
        fputs("garbage\n", f);
        fclose(f);
        memset(&geo, 0, sizeof(geo));
        keys = ic_geo_load("/tmp/ic-syms-bad.txt", &geo);
        expect("bad keys", (unsigned long long)keys, 1);
        expect("bad cred_req", geo.cred_req, 0xb0);
        expect("bad essential", (unsigned long long)geo.essential, 1);
    }

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("geo_test: all checks passed\n");
    return 0;
}
