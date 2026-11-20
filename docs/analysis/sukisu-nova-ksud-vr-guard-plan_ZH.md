# SukiSU Nova ksud 适配 + vr.ko W1c 全局拆除 计划（2026-11-20）

> English version: [sukisu-nova-ksud-vr-guard-plan.md](sukisu-nova-ksud-vr-guard-plan.md)

## 现状与基线

- 基线：fork 自 `YuKongA/ghostlock-app`（`6641116`，即上游 `main`）。
- ksud 供给链：App 侧 `ManagerScanner`/`resolveKsudPath` 按包名列表在
  `nativeLibraryDir` 找 `libksud.so`，经 `GHOSTLOCK_KSUD` 传给 native；root
  脚本（`ops.cpp`）再按同名 `find` 回退，最后退 `/data/local/tmp/ksud`、
  `/data/adb/ksu/bin/ksud`。内置列表覆盖 KernelSU、SukiSU Ultra、ReSukiSU、
  BakaSU、KowSU（PR #830 模式）。
- 问题 1：**SukiSU Nova 每次 release 构建都把打包的 `libksud.so` 改名为随机
  `lib<小写字母>.so`**（`.github/workflows/manager.yml` 的 randomize 步骤，
  JNI 核心库与组件类名同样随机化），按名字永远找不到；其 ksud 支持
  `late-load --kmi`（内核模块按 KMI 内嵌在二进制里），是 GhostLock 完整链路
  的合法提供方。
- 问题 2：上游已有 **W2b** 逐任务摘标（运行时 `/proc/modules` 探测门控），但缺
  **W1c** 全局拆除（清零 `__tracepoint_sys_exit->funcs`）与 profile 字段管线。
  vivo `vr.ko` 在任务持有 uid 0 后的下一次 `sys_exit` 处杀死该任务，W2b 无法
  覆盖 W2 之后 fork 的进程（ksud 及其子 shell）——这正是提权成功后模块加载
  失败的直接原因。改版（DONGDERS/Ghostlock-vr 一系）已在真机验证该防御；
  其配置（如 `z9turbo-FINAL.conf`）含 `recommend_vr_guard` / `vr_guard` /
  `offset.vr_sys_exit_tp` 字段，导入上游会被 `ProfileResolver` 判为
  "unknown top-level key"（即“正常版导入改版配置显示异常”）。

## 目标与约束

- 目标：SukiSU Nova（`com.sukisu.nova` 及其 `.pr` CI 构建）作为根管理器被自动
  检测并提供 ksud；vr 字段进 schema 与 wire；W1c 阶段落地；内置
  `6.1.145-android14-11-maybe-dirty`（vivo iQOO Z9 Turbo）profile。
- 非目标：不实现提权后自动软重启（hmascs issue #258 问题 1 的前提不成立，
  不软重启可正常使用）；不把 ksud 二进制打包进 GhostLock APK；不改 W2b
  现有逻辑；不处理 W1c 写入失败以外的 vr 变体（如 6.12 的 tag 偏移差异）。

## 改动清单

| 文件 | 改动 | 理由 |
|---|---|---|
| `app/src/main/AndroidManifest.xml` | `<queries>` 增加 nova 两包名 | 包可见性 |
| `app/.../data/ManagerScanner.kt` | BUILTIN 增加 nova 两包名；新增 `CONTENT_SCANNED`、`KSUD_SIGNATURE`（`late-load command triggered!`）、`hasKsud(pkg, dir)`、`findKsudByContent(dir)`（64 KiB 分块 + 尾部携带跨块匹配） | 随机库名按内容定位 |
| `app/.../data/AndroidGhostlockRepository.kt` | `resolveKsudPath`：名字匹配后对 `CONTENT_SCANNED` 包做内容探测 | 直连路径 |
| `app/.../shizuku/GhostlockUserService.kt` | 同上的双路径解析 | Shizuku 路径 |
| `src/core/attack/ops.cpp` | root 脚本回退链：nova 目录 `*.so` 逐个 `grep -F` 签名（`-size +1M` 预筛）；绝对路径回退补 `/data/adb/ksud` | CLI/回退路径；hmascs #258 建议 2 |
| `src/core/profile/model.h` | `KernelOffsets.sys_exit_tp_funcs`（0=未提供） | W1c 目标 |
| `src/core/profile/binary.cpp` | `PLAIN("sys_exit_tp_funcs", ...)` | wire 编解码 |
| `src/core/kernel/runtime_struct_offsets.h` | `sys_exit_tp_funcs_image()` / `sys_exit_tp_funcs_present()`（无编译期回退） | 缺字段必须禁用阶段而非猜 |
| `src/core/session/backend/cve_2026_43499_backend.cpp` | 抽出共享 `vr_module_loaded()`；新增 `w1c_neutralize_vr<M>()`（leaf=1 字面零写）；在 `w1` 后接线 `run_state` "w1c" | 全局拆除 |
| `profile-core/.../NativeProfile.kt` | `KernelOffsetTable.sysExitTpFuncs`；`from()` 双格式（直接字段优先，否则 `vr_sys_exit_tp + tracepoint_funcs`，半解析对为 0）；Builder/entries 同步 | 组合解析 |
| `profile-core/.../profile/ProfileResolver.kt` | `KnownTopLevel` += `recommend_vr_guard`、`vr_guard` | 消除导入误报 |
| `app/.../AndroidProfileConfigController.kt` | 叶子过滤 += `recommend_vr_guard`（两处） | 推荐位不进编辑器，与 shizuku 一致 |
| `app/.../LegacyProfileConverter.kt` | `OffsetFields` += `sys_exit_tp_funcs`、`vr_sys_exit_tp`；dev 格式 `struct_fields.vr_tracepoint_funcs` → `vr_guard.tracepoint_funcs` | v1/dev 报告导入 |
| `app/.../ui/FieldLabels.kt` + `values{,-zh}/strings.xml` | 三个字段标签 | UI 显示 |
| `app/src/main/assets/kernel_profiles/6.1.145-android14-11-maybe-dirty.conf` | 新增（Z9 Turbo 本机 dump 值，与验证过的 `z9turbo-FINAL.conf` 逐字段一致） | 内置配置 |
| `app/src/main/assets/kernel_profiles/index.conf` | 登记该 release | 索引 |
| `docs/kernel_profiles/SUPPORTED_DEVICES{,_ZH}.md` | 增加行 | 登记表 |
| `docs/kernel_profiles/PROFILE_SCHEMA{,_ZH}.md` | 4.3 表增加 vr 三行 | 字段参考 |
| 测试：`ManagerScannerTest` / `ManagerScannerScanTest` | BUILTIN/顺序/内容探测（随机名 + JNI 干扰库）/非扫描包不受内容探测 | 回归 |

## 数据流/控制流差异

- ksud 解析：名字匹配 →（`CONTENT_SCANNED` 包）内容签名。签名是 late-load
  阶段的 Rust 日志句，存在于全家（KernelSU/Ultra/Nova/Next/BakaSU/KowSU/
  KiMiSU/DiKSU）已核对的 ksud 二进制中；nova 的 JNI 胶水库只含裸参数串
  `"late-load"`（`jni.cc` 的 `execl`），不含该句，不会误报。
- 控制流：`w1 → w1c → (W2+W3 链)`。W1c 仅在 `/proc/modules` 探测到 `vr*`
  模块且 profile 提供目标偏移时执行一次 leaf 写；失败仅降级（W2b 仍在），
  不使运行失败。`run_state` 新增 `w1c` 步（事件自由文本，无白名单）。
- 不变量：无 vr 字段的旧 profile `sys_exit_tp_funcs=0` → W1c 跳过，行为与
  基线一致；wire 只增不改（新键自描述，旧 reader 跳过未知键）。

## 兼容性与回滚

- 配置：旧 conf 不受影响；改版 conf（含 vr 字段）从“导入报错”变为“正常解析”。
- 二进制 wire：`offset` 段新增键；Kotlin 与 native 同批发布（App 打包
  `libghostlock.so`），无跨版本混跑。
- 回滚：revert 单个 commit 即可；conf/索引/文档改动无运行时副作用。

## 验证矩阵

| 项 | 命令/方法 | 结果 |
|---|---|---|
| 签名覆盖 | 对 nova v3.0.0 官方 ksud 与 5 个改版内置 ksud `grep -F` | 6/6 命中 |
| shell 回退 | 伪造 `/data/app` 树（真实 nova ksud 随机名 + JNI/adbroot/kptools 干扰），跑回退链脚本 | 命中目标文件，负对照 0 误报 |
| 分块扫描 | Python 移植算法：空/5B/27B/28B/块内/跨块/块尾 | 全部通过（含 `minOf` 携带修复） |
| 内置 conf | 模拟 App 管线（include 展开 → HOCON 解析 → 校验 → 与验证配置逐字段比对） | 61 字段一致，W1c 组合 = 37532416 |
| C++ 语法 | `g++ -fsyntax-only -std=c++23`（backend/ops/binary/accessors，带 `TARGET_CONFIG_H`） | 0 error |
| 单元测试 | `./gradlew :app:testDebugUnitTest`（含 `BuiltinProfilesTest` 全量内置遍历） | 待 CI/本地跑（本环境无 Android SDK） |
| native 测试 | `make -C src native-host-tests` | 待跑 |
| 真机门禁 | Z9 Turbo：执行 → `w1c` 状态行 → `[+] KernelSU module loaded`（nova 管理器显示工作中） | 待真机 |

## 明确保留

- W2b 摘标逻辑与 `VR_TAG_B_OFF` 宏不动（仅把内联探测换成共享函数）。
- 其余管理器的名字匹配路径不动；`CONTENT_SCANNED` 之外不做全局内容扫描。
- v1 转换的既有行为不变（新增键只影响携带这些键的新输入）。
- 软重启相关：不实现（#258 问题 1 前提不成立）。

## 进度

- [x] 调查：nova 随机化机制、签名选取、vr 字段双格式、W1c 实现
- [x] ksud + SukiSU Nova（App/Shizuku/root 脚本/测试/文档）
- [x] vr_guard schema + wire + W1c
- [x] 内置 Z9 Turbo profile + 登记
- [x] 主机侧验证（签名/shell/HOCON/语法）
- [ ] `:app:testDebugUnitTest` / `native-host-tests`（需 Android SDK/NDK）
- [ ] 真机门禁（Z9 Turbo）
