# TimerRoot 漏洞利用链 + vr.ko 偏移提取 设计方案

状态：已实施（分支 `feat/timerroot-vr-extract`）。本文记录设计决策与验证矩阵，
按 `docs/development/design-philosophy.md` 的 L 级改动流程撰写。

## 0. 背景与目标

用户需求（2026-11-20）：

1. 在 CPU 核心组选项上方加「漏洞利用链」选择：Ghostlock（CVE-2026-43499）/
   TimerRoot（CVE-2026-98260）。
2. TimerRoot 链参考 `xxTurborocketxx/TimerRoot`（原仓库已下线，以其发行 APK
   `com.ksu.cve98260 2.3.8` 的反编译为接口契约）与上游 `kzktor/ic-timer-lpe`
   （GPL-3.0）。
3. 「移植解析」：GhostLock 的提取器（`tools/extract_rs`）新增 `--format ic-syms`
   输出，从 boot.img / OTA 恢复 kallsyms 并生成 t98260 需要的 66 符号表。
4. 「vr.ko 偏移提取」：
   - boot.img 侧：移植 DONGDERS/Ghostlock-vr 的 `derive_sys_exit_tp_funcs`
     （反汇编 `__traceiter_sys_exit` 推导 `__tracepoint_sys_exit->funcs`）；
   - vendor_boot 侧：移植 hmascs PR #257 的 vendor_ramdisk 探测
     （VNDRBOOT → LZ4-legacy → cpio newc → vr.ko → ELF 扫描 tag A/B 偏移）。
   vr.ko 提取器形态参考 DONGDERS/DirtyFalg-vr（其 `vrext` 本身就是以 GhostLock
   提取器为 path 依赖实现的，证明该管线可行）。
5. libksud.so 手动选择：先用内容签名（PR #830 引入的
   `late-load command triggered!`）识别，再让用户在列表里自选任意 `.so`
   作为 libksud.so（参考 APK 的 `ManagerPickerActivity` 交互）。
6. 98260 与 43499 的配置加载界面：**分离**（理由见 §3）。
7. 仓库整体转 GPL-3.0（因移植 ic-timer-lpe 的符号表格式与 vr.ko 探测逻辑），
   致谢 hmascs / YuKongA / DONGDERS / kzktor 等。

## 1. 漏洞利用链选择（ExploitChain）

- `domain/model/GhostlockModels.kt`：新增 `ExploitChain { GHOSTLOCK, TIMER_ROOT }`。
- 持久化：`ghostlock_prefs` 的 `exploit_chain`（默认 GHOSTLOCK，兼容旧安装）。
- UI：主界面 Card 内、CPU 核心组 Spinner 上方加一个 `OverlaySpinnerPreference`，
  两项：`Ghostlock (CVE-2026-43499)` / `TimerRoot (CVE-2026-98260)`。
- Run 行为分流：
  - GHOSTLOCK：现状不变（本地 ProcessBuilder 或 Shizuku 跑原生管线）。
  - TIMER_ROOT：强制 Shizuku 路径（98260 需要读 tracefs，必须 shell 域执行；
    与参考 APK 相同），未开 Shizuku 时给出明确提示并拒绝运行。

## 2. TimerRoot 链的执行契约（从参考 APK 反编译还原）

参考 APK（`com.ksu.cve98260`）的 Shizuku 路径：

```
app(untrusted) ──AIDL──> Shizuku UserService(shell, Seccomp=0)
  unzip -p <own apk> assets/t98260 > /data/local/tmp/t98260; chmod 755
  unzip -p <manager apk> <所选 so> > /data/local/tmp/ksud; chmod 755
  env IC_HOME=<dir> T28_NO_HOLD=1 IC_PLANT_ATTEMPTS=32
      IC_DISCOVER_ATTEMPTS=16 IC_DISCOVER_WAIT_MS=1000
      [IC_SYMS_FILE=<表>] [IC_TASK_CRED=0x..] [IC_CRED_UID=0x4]
      /data/local/tmp/t98260 ksu > ic.log 2>&1 &
  轮询 ic.log / ku-load.log，等待 "KernelSU module loaded"
```

我们的实现差异（改进，非照抄）：

- 所有工件落在 UserService 的 workDir（`/data/local/tmp/ghostlock-app/`，
  shell 可写、root 可写），不用 app filesDir——避免 shell 读 0700 目录的
  DAC 风险；ic-syms 表内容经 AIDL 传字符串，由服务端写文件。
- t98260 二进制两个来源：
  1. **内置**：`app/src/main/assets/t98260`（构建时若存在则打包；CI 不携带，
     运行时检测）。README 说明来源（ic-timer-lpe 构建产物）。
  2. **用户导入**：SAF 选择本地二进制，> binder 1MB 限制，分片 AIDL
     （`pushTimerRootBinary`）由服务端拼装。
- ksud 提取源 = 用户在 libksud.so 选择器中的选择（见 §4）；未选择时用
  ManagerScanner 的自动解析（libksud.so → 内容签名探测）。
- 成功判定与卡死判定沿用参考 APK：日志含 `KernelSU module loaded` /
  `late-load`，90 秒无进展提示重启。

## 3. 配置加载界面：分离（结论）

**分离，但同一入口切换**。理由：

- 43499 的配置是 HOCON kernel_profiles（偏移 + 执行调参 + route），有
  合并/覆盖/导出/用户配置库一整套生命周期；
- 98260 的配置是「ic-syms 符号表 + t98260 二进制」，格式与生命周期完全
  不同（符号表只跟内核 build 相关，无执行调参）；
- 混在同一界面会让「导入改版配置显示异常」这类问题再次出现。

实现：主界面「配置」卡片内容随 exploit chain 切换——GHOSTLOCK 显示现有
profile 状态；TIMER_ROOT 显示二进制状态（内置/已导入/缺失+导入按钮）与
符号表状态（当前内核是否已解析/缺失+解析按钮/导入按钮）。解析入口复用
现有 parseSource 流程（boot.img / OTA / URL），新增输出格式 ic-syms。

## 4. libksud.so 手动选择（列表 UI）

- 新组件「ksud 库」选择对话框（`KsudLibraryPickerDialog`）：
  - 数据源：所选管理器 APK 内 `lib/arm64-v8a/*.so` 的 zip 条目（名称+大小，
    与参考 APK 一致按大小降序；nativeLibraryDir 里没有的（如已抽稀的
    extractNativeLibs=false 场景）也能看到）。
  - 每行显示：文件名（粗体）、完整 zip 路径（小字）、大小；≥4 MiB 标
    「推荐」徽章（参考 APK 的 RECOMMEND_BYTES 语义）；内容签名命中的
    条目标「检测为 ksud」徽章（= 我们自己的标识，`late-load command
    triggered!`，ManagerScanner.KSUD_SIGNATURE）。
  - 顶部固定一项「自动（推荐）」= 现有解析逻辑。
  - 选择持久化：`ksud_library_choice`（"auto" 或 zip 条目名）。
- 生效路径：
  - Ghostlock 链：UserService 解析 ksud 时，若 choice != auto，则从管理器
    APK `unzip -p` 提取到 workDir/ksud 并以 `GHOSTLOCK_KSUD` 传入原生
    进程；auto 时维持现状（nativeLibraryDir/内容签名）。
  - TimerRoot 链：UserService 直接 `unzip -p` 提取所选条目为
    /data/local/tmp/ksud（参考 APK 的做法）。

## 5. 提取器（tools/extract_rs）改动

### 5.1 `--format ic-syms`（98260 符号表）

- 新增 `report::write_ic_syms()`：输出 ic-timer-lpe `ic_syms.h` 定义的表
  格式（`# build=` / `# version=` 头 + `name=0xADDR` 行），符号集 =
  `ic_syms_required[]` 的 66 个（58 个投票锚点 + 8 个目标/可选）。
- 符号全部来自既有 kallsyms 恢复；缺失的锚点符号跳过并 stderr 警告
  （t98260 对锚点缺失有自己的降级），4 个目标符号缺失则报错。
- 复用现有输入管线：boot.img / payload.bin / OTA zip / URL 一律可用。

### 5.2 `derive_sys_exit_tp_funcs`（boot.img → vr.ko W1c 目标）

从 DONGDERS/Ghostlock-vr 的 `derive.rs` 移植：

- `tracepoint_funcs_field()`：在 `__traceiter_sys_exit` 反汇编里找
  `adrp+ldr+cbz` 签名，取 ldr 的「BTF funcs 成员偏移 + 结构基址」；
  交叉校验：`__tracepoint_sys_exit->funcs` 与 `__tracepoint_sys_enter->funcs`
  必须恰差 `sizeof(struct tracepoint)`。
- kallsyms 有 `__tracepoint_sys_exit` 数据符号时（KALLSYMS_ALL）直接用；
  否则用反汇编推导（DirtyFalg-vr `vrext` 同款算法）。
- 输出：conf 的 `offset.sys_exit_tp_funcs`（上一批已进 profile 模型）。

### 5.3 vendor_boot vr.ko 探测（PR #257 移植）

`vendor_boot.rs` 新增 `probe_vrko()`：

1. 校验 VNDRBOOT 魔数与 header v3/v4，取 vendor_ramdisk（header_size 对齐
   page_size 后起始，长度受文件边界约束）；
2. LZ4-legacy 解压（复用 `boot.rs` 的解码器）；
3. cpio newc 遍历（`parse_hex8` 定宽解析防吞位），收集 `lib/modules/*vr.ko`，
   优先精确路径 `lib/modules/vr.ko`；
4. ELF64 节表扫描可执行节，找 `mrs xN, sp_el0`（0xD5384100 掩码）后
   8 条指令窗口内同寄存器的 `strb/ldrb`（0x39000000/0x39400000），
   第一个 imm = tag A，第二个不同 imm = tag B；
5. 输出 `vr_tag_offset_a` / `vr_tag_offset_b` 进 conf 与 JSON。

### 5.4 profile 模型与 W2b

- `profile/model.h`：`KernelOffsets` 增 `vr_tag_a` / `vr_tag_b`（无编译期
  回退，缺失即关闭该路径——与 sys_exit_tp_funcs 同策略）。
- W2b（`cve_2026_43499_backend.cpp`）：tag A 仍由 thread_info.flags 整字
  清除覆盖（现状，6.1/6.6/6.12 实测族 tag A=0x06 均落在 flags 字内），
  tag B 改为 profile 提供 `vr_tag_b` 时按 64 位对齐清零，缺失时维持硬编码
  0x2c 兼容旧配置。wire（binary.cpp）、Kotlin NativeProfile、v1 转换器、
  字段文案与 schema 文档同步。

## 6. Shizuku AIDL 扩展

`IGhostlockUserService.aidl` 新增：

```
void runTimerRoot(String managerApk, String ksudEntry,
                  in byte[] symsBlob, String symsName,
                  boolean safeMode, IGhostlockCallback callback);
void pushTimerRootBinary(in byte[] chunk, int offset, int total);
```

- `runTimerRoot`：内置 assets/t98260 存在则 `unzip -p` 落盘；否则用
  `pushTimerRootBinary` 已拼装的用户二进制；两者皆无 → 报错并提示。
  ksud 提取、脚本物化（ksu-handoff 脚本以 workDir 为 HOME）、env 组装、
  后台启动 + 日志 tail 全部在服务端完成。
- 分片传输：app 侧 512 KiB 分片，服务端按 offset 顺序追加到 workDir。

## 7. 协议与致谢

- LICENSE：Apache-2.0 → GPL-3.0（全文）。移植物来自 GPL-3.0 项目
  （ic-timer-lpe 符号表格式与算法、vr.ko 探测、DONGDERS/Ghostlock-vr 的
  反汇编推导），GPL-3.0 第 5/7 条要求整体以 GPL 分发。
- README.md 重写为中文（shields 徽章 + 社区规范结构），原英文版移至
  README_EN.md；顶部加语言切换链接。
- 致谢（用于 README 与关于页）：
  - `YuKongA/ghostlock-app`：上游本体；
  - hmascs：PR #257 的 vr.ko 探测与中和研究（vendor_boot 探测、
    tracepoint 常量文档）、KSuRoot；
  - DONGDERS：Ghostlock-vr（W1c/disarm 与反汇编推导）与 DirtyFalg-vr
    （vrext 提取器形态）；
  - kzktor/ic-timer-lpe（酷安 @散花神木，GPL-3.0）：CVE-2026-98260 移植
    与符号表格式；
  - xxTurborocketxx/TimerRoot：TimerRoot 前端交互参考；
  - SukiSU-Nova / KernelSU / Shizuku / miuix。
- AboutUI：版本卡片下新增「开源许可与致谢」段落（GPL-3.0 + 上列表）。

## 8. 验证矩阵

| 项 | 命令 | 期望 |
| --- | --- | --- |
| Rust 提取器单测 | `(cd tools/extract_rs && cargo test --release)` | 全绿（含新增 ic-syms/derivation/vendor_boot 用例） |
| ic-syms 符号集 | 对合成 Image 跑 `--format ic-syms` | 66 必需符号全部出现，头部 build/version 正确 |
| vr.ko 探测 | 合成 VNDRBOOT+LZ4+cpio+假 vr.ko | tag A/B 解析正确；损坏输入逐级报错 |
| W1c 推导 | kallsyms 缺 `__tracepoint_sys_exit` 的合成 Image | 反汇编路径给出 funcs 偏移，交叉校验生效 |
| Kotlin 单测 | `./gradlew :app:testDebugUnitTest` | 全绿（ksud 选择器排序/持久化、链切换、ic-syms 存储） |
| APK 构建 | `./gradlew :app:assembleDebug`（CI） | 成功；无 assets/t98260 时 APK 照常构建 |
| 双侧一致性 | `NativeProfileDocumentTest` 等既有测试 | 新字段 wire 双侧同步被测试抓住 |

真机验证（无设备，列为待办）：TimerRoot 链端到端、vr tag 偏移对
6.1.145 the target vivo 6.1.145 firmware 生效、手动 ksud 选择对 SukiSU Nova 随机名生效。

## 9. 明确不做

- 不把 t98260 的利用本体（timer98260.c，3.9k 行 C）移植进 `src/core`
  原生管线——独立二进制经 Shizuku 执行是参考 APK 验证过的形态，且
  避免与 43499 管线的 PI 竞争窗口互相干扰。
- 不实现参考 APK 的「无线调试自助配对 + 内嵌 adb」路径（我们已有 Shizuku）。
- 不在 CI 里构建 t98260（避免 vendor GPL 源树；用户自备或本地放置）。
