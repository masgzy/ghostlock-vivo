# SukiSU Nova ksud support + vr.ko W1c global disarm plan (2026-11-20)

> 简体中文：[sukisu-nova-ksud-vr-guard-plan_ZH.md](sukisu-nova-ksud-vr-guard-plan_ZH.md)

## Baseline

- Base: fork of `YuKongA/ghostlock-app` (`6641116`, upstream `main`).
- ksud provisioning chain: the app (`ManagerScanner`/`resolveKsudPath`) matches
  `libksud.so` by package name under `nativeLibraryDir` and passes it to native
  via `GHOSTLOCK_KSUD`; the root script (`ops.cpp`) repeats the same-name `find`
  fallback and finally falls back to `/data/local/tmp/ksud` and
  `/data/adb/ksu/bin/ksud`. Built-ins: KernelSU, SukiSU Ultra, ReSukiSU,
  BakaSU, KowSU (the PR #830 pattern).
- Problem 1: **SukiSU Nova renames the packaged `libksud.so` to a random
  `lib<lowercase>.so` on every release build** (the randomize step in
  `.github/workflows/manager.yml`; the JNI core library and component class
  names are randomized as well), so a name match can never succeed. Its ksud
  supports `late-load --kmi` (per-KMI kernel modules are embedded in the
  binary) and is a legitimate provider for the full GhostLock chain.
- Problem 2: upstream already has the **W2b** per-task tag clear (gated by the
  runtime `/proc/modules` probe) but lacks the **W1c** global disarm (zeroing
  `__tracepoint_sys_exit->funcs`) and the profile plumbing. vivo's `vr.ko`
  kills a task on its next `sys_exit` once it holds uid 0; W2b cannot cover
  tasks forked after W2 (ksud and the shells it spawns) — the direct cause of
  module loading failing right after a successful escalation. The modified
  builds (the DONGDERS/Ghostlock-vr lineage) have the defense verified
  on-device; their configs (e.g. `z9turbo-FINAL.conf`) carry
  `recommend_vr_guard` / `vr_guard` / `offset.vr_sys_exit_tp`, which
  `ProfileResolver` rejects as "unknown top-level key" on upstream (the
  "normal build shows garbage when importing the modified build's config"
  symptom).

## Goals and constraints

- Goals: auto-detect SukiSU Nova (`com.sukisu.nova` plus the `.pr` CI build) as
  a root manager and use its ksud; land the vr fields in schema and wire; add
  the W1c stage; add the built-in `6.1.145-android14-11-maybe-dirty` profile
  (vivo iQOO Z9 Turbo).
- Non-goals: no post-escalation auto soft reboot (the premise of hmascs issue
  #258 problem 1 does not hold — no reboot is needed); no ksud binaries
  bundled into the GhostLock APK; no changes to the W2b logic; no handling of
  other vr variants (e.g. the 6.12 tag-offset differences).

## Change list

| File | Change | Reason |
|---|---|---|
| `app/src/main/AndroidManifest.xml` | add both nova package names to `<queries>` | package visibility |
| `app/.../data/ManagerScanner.kt` | add both nova names to BUILTIN; add `CONTENT_SCANNED`, `KSUD_SIGNATURE` (`late-load command triggered!`), `hasKsud(pkg, dir)`, `findKsudByContent(dir)` (64 KiB chunks + tail carry for straddling matches) | locate the randomized library by content |
| `app/.../data/AndroidGhostlockRepository.kt` | `resolveKsudPath`: after the name match, content-probe `CONTENT_SCANNED` packages | direct path |
| `app/.../shizuku/GhostlockUserService.kt` | the same dual-path resolution | Shizuku path |
| `src/core/attack/ops.cpp` | root script fallback: `grep -F` the signature over the nova dir's `*.so` (with a `-size +1M` pre-filter); add `/data/adb/ksud` to the absolute-path fallbacks | CLI/fallback path; hmascs #258 suggestion 2 |
| `src/core/profile/model.h` | `KernelOffsets.sys_exit_tp_funcs` (0 = not provided) | W1c target |
| `src/core/profile/binary.cpp` | `PLAIN("sys_exit_tp_funcs", ...)` | wire codec |
| `src/core/kernel/runtime_struct_offsets.h` | `sys_exit_tp_funcs_image()` / `sys_exit_tp_funcs_present()` (no compile-time fallback) | a missing field must disable the stage, not guess |
| `src/core/session/backend/cve_2026_43499_backend.cpp` | extract the shared `vr_module_loaded()`; add `w1c_neutralize_vr<M>()` (leaf=1 literal-zero write); wire it after `w1` with `run_state` "w1c" | global disarm |
| `profile-core/.../NativeProfile.kt` | `KernelOffsetTable.sysExitTpFuncs`; `from()` dual format (direct field wins, otherwise `vr_sys_exit_tp + tracepoint_funcs`, a half-resolved pair stays 0); Builder/entries kept in sync | composed resolution |
| `profile-core/.../profile/ProfileResolver.kt` | `KnownTopLevel` += `recommend_vr_guard`, `vr_guard` | stop rejecting imported configs |
| `app/.../AndroidProfileConfigController.kt` | leaf filters += `recommend_vr_guard` (two places) | advisory bit stays out of the editors, same as shizuku |
| `app/.../LegacyProfileConverter.kt` | `OffsetFields` += `sys_exit_tp_funcs`, `vr_sys_exit_tp`; dev-format `struct_fields.vr_tracepoint_funcs` -> `vr_guard.tracepoint_funcs` | v1/dev report import |
| `app/.../ui/FieldLabels.kt` + `values{,-zh}/strings.xml` | three field labels | UI display |
| `app/src/main/assets/kernel_profiles/6.1.145-android14-11-maybe-dirty.conf` | new (Z9 Turbo on-device dump values, field-identical to the verified `z9turbo-FINAL.conf`) | built-in profile |
| `app/src/main/assets/kernel_profiles/index.conf` | register the release | index |
| `docs/kernel_profiles/SUPPORTED_DEVICES{,_ZH}.md` | add the row | registry |
| `docs/kernel_profiles/PROFILE_SCHEMA{,_ZH}.md` | three vr rows in the 4.3 table | field reference |
| tests: `ManagerScannerTest` / `ManagerScannerScanTest` | BUILTIN/order/content probe (randomized name + JNI decoy)/non-scanned packages are not content-probed | regression |

## Dataflow / control-flow differences

- ksud resolution: name match -> (for `CONTENT_SCANNED` packages) content
  signature. The signature is the late-load stage's Rust log sentence, present
  in every ksud binary checked across the family (KernelSU/Ultra/Nova/Next/
  BakaSU/KowSU/KiMiSU/DiKSU); nova's JNI glue library only carries the bare
  argument string `"late-load"` (the `execl` in `jni.cc`), never the sentence,
  so it cannot false-positive.
- Control flow: `w1 -> w1c -> (W2+W3 chain)`. W1c runs once only when the
  `/proc/modules` probe sees a `vr*` module and the profile provides the
  target offset; a miss only degrades (W2b still runs) and never fails the
  run. `run_state` gains the `w1c` step (free-text events, no whitelist).
- Invariants: an old profile without vr fields has `sys_exit_tp_funcs = 0`,
  W1c is skipped and behavior matches the baseline; the wire only gains keys
  (self-describing; old readers skip unknown keys).

## Compatibility and rollback

- Configs: old confs are unaffected; modified-build confs (with vr fields) go
  from "import error" to "resolves cleanly".
- Binary wire: one new key in the `offset` section; Kotlin and native ship in
  the same APK (`libghostlock.so`), so there is no cross-version mixing.
- Rollback: revert the commit; the conf/index/docs changes have no runtime
  effect on their own.

## Verification matrix

| Item | Command/method | Result |
|---|---|---|
| Signature coverage | `grep -F` over the official nova v3.0.0 ksud and the five bundled variant binaries | 6/6 matched |
| Shell fallback | fake `/data/app` tree (real nova ksud under a random name + JNI/adbroot/kptools decoys), run the fallback chain script | target hit, negative control 0 false positives |
| Chunked scan | Python port of the algorithm: empty/5B/27B/28B/in-chunk/straddle/chunk-edge | all pass (including the `minOf` carry fix) |
| Built-in conf | simulate the app pipeline (include expansion -> HOCON parse -> validation -> field-by-field diff against the verified config) | 61 fields identical, W1c composition = 37532416 |
| C++ syntax | `g++ -fsyntax-only -std=c++23` (backend/ops/binary/accessors, with `TARGET_CONFIG_H`) | 0 errors |
| Unit tests | `./gradlew :app:testDebugUnitTest` (includes the full `BuiltinProfilesTest` sweep) | pending CI/local (no Android SDK in this environment) |
| Native tests | `make -C src native-host-tests` | pending |
| Device gate | Z9 Turbo: run -> the `w1c` status line -> `[+] KernelSU module loaded` (the nova manager shows working) | pending on-device |

## Explicitly preserved

- The W2b tag-clear logic and the `VR_TAG_B_OFF` macro are untouched (only the
  inlined probe became the shared function).
- The name-match path for the other managers is untouched; no global content
  scan outside `CONTENT_SCANNED`.
- The existing v1 conversion behavior is unchanged (new keys only affect new
  inputs that carry them).
- Soft reboot: not implemented (the premise of #258 problem 1 does not hold).

## Progress

- [x] Investigation: nova randomization, signature choice, dual vr format, W1c implementation
- [x] ksud + SukiSU Nova (app/Shizuku/root script/tests/docs)
- [x] vr_guard schema + wire + W1c
- [x] built-in Z9 Turbo profile + registration
- [x] host-side verification (signature/shell/HOCON/syntax)
- [ ] `:app:testDebugUnitTest` / `native-host-tests` (needs Android SDK/NDK)
- [ ] device gate (Z9 Turbo)
