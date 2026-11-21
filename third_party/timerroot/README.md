# third_party/timerroot — vendored CVE-2026-98260 (TimerRoot) core

Vendored from **xxTurborocketxx/TimerRoot** `core/` (GPL-3.0), which itself
carries the lineage of **kzktor/ic-timer-lpe** (GPL-3.0, by Coolapk
@散花神木) and **molanp/CVE-2026-98260-vivo-s60-poc** (MIT, adapted from
woshigenm/CVE-2026-98260, MIT). See `LICENSE.molanp` for the MIT notice of
the baseline core and the repository-wide `LICENSE` (GPL-3.0) that governs
this fork's copy.

## What changed here

The upstream core compiled **one kernel profile per binary** (`profiles.h`,
selected with `-DIC_PROFILE_<name>`): a binary built for one firmware
refused to run on any other (`kernel ... does not match profile ...`).

This copy keeps the compiled profile as a fallback default (PD2571,
6.1.145-android14) but makes every kernel-specific number loadable at
runtime from the **extended ic-syms table**:

- `ic_syms.{c,h}` gained `ic_geo_load()` and `struct ic_geo`: the table may
  now carry `off.<name>=0xVALUE` geometry lines (struct sizes and field
  offsets) next to the classic `name=0xADDR` symbol lines.
- `timer98260.c` routes every profile constant through `G_*` accessors that
  prefer the table value and fall back to the compiled constant.
- The kernel gate moved after the table load and now also accepts a
  **table-driven run**: build banner matches `uname` AND all 16 essential
  geometry keys present. `IC_ALLOW_ANY_KERNEL` still force-bypasses.
- When the compiled profile does not match `uname`, `g_static_ok` is
  cleared: the slide is derived from the observed timer call site (2 MiB
  low21 rule) and every link address comes from the table — never from the
  profile's `STATIC_*` addresses of a different image.
- `defeat_vr()` prefers the staged table's `__tracepoint_sys_exit` over the
  profile constant (mixed runs: version matches, image differs).
- `t98260 info` reports `geom=<essential>/<total>` and `tblbuild=` so an
  app can preflight a table-driven run.

The GhostLock extractor emits the geometry block automatically from the
image's BTF (`--format ic-syms`), so parsing a full OTA / boot.img in the
app produces a complete table. The format is documented in
`docs/timerroot-config.md` at the repository root.

## Build

```sh
# static executable (same as upstream)
./build.sh /tmp/t98260 pd2571

# packaged as a jniLib for the APK: the file name is the only difference —
# Android extracts any lib*.so from jniLibs, and the Shizuku runner stages
# it to /data/local/tmp and execs it there.
./build.sh app/src/main/jniLibs/arm64-v8a/libtimerroot.so pd2571
```

The Gradle build invokes the second form (`buildTimerRootNative` /
`prepareTimerRootJniLibs` in the root `build.gradle.kts`); CI builds it
with the same NDK as the GhostLock core.

## Tests

```sh
cc -Wall -Wextra -I. -DIC_SYMS_HAVE_ZLIB tests/geo_test.c ic_syms.c -lz -o geo_test
./geo_test tests/ic-syms-geo.txt
```

CI runs this host test on every build.

## Upstream layout kept as-is

`timer98260.c` (single-TU exploit), `ic_syms.c` (boot.img/Image/vmlinux/
System.map symbol recovery), `profiles.h` (compile-time profiles),
`anchors.h` / `extra_syms.h` (per-build link tables), `tools/` (porting
scripts: `make_port.py`, `derive_offsets.py`, `disasm_kernel.py`,
`verify_tables.py`).
