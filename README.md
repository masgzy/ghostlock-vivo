# GhostLock-vivo

[English](README_EN.md) | **中文**

![Build](https://shields.io/github/actions/workflow/status/masgzy/ghostlock-vivo/build.yml?branch=main&label=CI)
![License](https://shields.io/github/license/masgzy/ghostlock-vivo)
![Release](https://shields.io/github/v/tag/masgzy/ghostlock-vivo?label=release&sort=semver)
![API](https://shields.io/badge/Android%2012%2B-arm64%20v8a-green)
![Kernel](https://shields.io/badge/CVE--2026--43499%20%7C%20CVE--2026--98260-PI%20futex%20%7C%20POSIX%20timer-blue)

GhostLock 的 vivo 适配 fork：在支持的 Android 内核上获取临时 root 并加载 KernelSU 系管理器，新增 **vr.ko 反检测中和**、**vendor_boot vr.ko 偏移探测**与 **TimerRoot（CVE-2026-98260）漏洞利用链**。

> [!WARNING]
> 内核利用工具。仅可在你拥有的设备上使用；操作失败可能导致内核崩溃或数据丢失。重启是唯一的干净回退方式。

## 功能特性

- **双漏洞利用链**（主界面可选）：
  - **Ghostlock（CVE-2026-43499）**——原生 PI-futex 竞争管线（W1/W2/W3 → root child → KernelSU late-load）；
  - **TimerRoot（CVE-2026-98260）**——POSIX CPU timer UAF 链，经 Shizuku 以 shell 域运行 `t98260` 二进制，并完成 ksud 交接（基于 [kzktor/ic-timer-lpe](https://github.com/kzktor/ic-timer-lpe)，GPL-3.0）。
- **vr.ko 反 root 检测中和**（vivo 设备）：
  - W1c 全局解除 `__tracepoint_sys_exit` 探针（boot.img 反汇编推导，kallsyms 缺符号时也能定位）；
  - W2b 每任务标签清除，标签偏移从 `vendor_boot.img` 的 `lib/modules/vr.ko` 实时探测（`--vendor-boot`）。
- **ic-syms 符号表解析**：提取器新增 `--format ic-syms`，从 boot.img / OTA ZIP / URL 生成 t98260 需要的 66 符号表。
- **libksud.so 手动选择**：先用内容签名（`late-load command triggered!`）自动识别，再允许在管理器 APK 的 `lib/arm64-v8a` 库列表中手动指定任意 `.so` 作为 ksud。
- **SukiSU Nova 支持**：随机命名的 `lib<random>.so` 通过内容签名检测；内置 6.1.145（the target vivo 6.1.145 firmware）等 vivo 配置。

## 使用

### 准备

1. 从 [KernelSU](https://github.com/tiann/KernelSU)、[SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)、[SukiSU Nova](https://github.com/SukiSU-Nova/SukiSU-Nova)、[BakaSU/ReSukiSU](https://github.com/Baka-SU/BakaSU) 或 [KowSU](https://github.com/KOWX712/KernelSU) 下载并安装管理器 APK。
2. 安装 GhostLock APK 并打开。
3. 需要时在 **设置 → Shizuku** 开启并通过 ADB / 无线调试启动 Shizuku。

### Ghostlock 链（CVE-2026-43499）

确认内核受支持后点击 **执行**。内核必须精确匹配 `uname -r`，请在[支持设备列表](docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md)中核对。

### TimerRoot 链（CVE-2026-98260）

1. 漏洞利用链选择 **TimerRoot**，进入 **TimerRoot 配置**：
   - **t98260 二进制**：将 [kzktor/ic-timer-lpe](https://github.com/kzktor/ic-timer-lpe) 构建的 `ic-timer` 复制为 `app/src/main/assets/t98260` 后打包，或在配置页导入；
   - **ic-syms 符号表**：输入 boot.img / OTA ZIP 路径或 URL 解析，或导入现成表（内置偏移已覆盖的机型可跳过）。
2. 确保 Shizuku 已启动（该链必须运行在 shell 域读取 tracefs）。
3. 点击 **执行**。成功后 KernelSU 模块加载并拉起管理器。

### 配置文件说明

- **Ghostlock 链**使用 HOCON kernel profile（导入 / 解析 / 编辑 / 导出，见[适配指南](docs/kernel_profiles/README_ZH.md)）；
- **TimerRoot 链**使用 ic-syms 符号表，两者界面按链切换、互不干扰。
- 联发科镜像地址提取见[联发科指南](docs/kernel_profiles/MEDIATEK_ZH.md)。

## 命令行工具

<details>
<summary>导出 profile 并运行原生程序</summary>

需要 Android NDK、`make`、Gradle 和 ADB。

```sh
make -C src ghostlock
./gradlew exportKernelProfiles
adb push build/native/ghostlock /data/local/tmp/ghostlock
adb push "build/kernel-profiles/<release>.bin" /data/local/tmp/profile.bin
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin
```

</details>

<details>
<summary>编译并运行偏移提取器</summary>

需要 Rust。支持 boot 镜像、完整 OTA ZIP 或 HTTP(S) 链接；`--vendor-boot` 附带 vr.ko 探测。

```sh
(cd tools/extract_rs && cargo build --release)
# Ghostlock HOCON profile
build/extract/release/ghostlock-extract boot.img --xbl-config xbl_config.img --format conf --out profile.conf
# 附带 vendor_boot 的 vr.ko 标签偏移（写入 offset.vr_tag_a / vr_tag_b）
build/extract/release/ghostlock-extract boot.img --vendor-boot vendor_boot.img --format conf --out profile.conf
# TimerRoot ic-syms 符号表
build/extract/release/ghostlock-extract OTA.zip --format ic-syms --out ic-syms.txt
```

</details>

## 构建

```sh
./gradlew :app:assembleDebug      # App(可选: 把 ic-timer 产物放到 app/src/main/assets/t98260)
(cd tools/extract_rs && cargo test --release)
./gradlew :app:testDebugUnitTest  # 单元测试(CI 同步执行)
```

CI（GitHub Actions）在每次 push / PR 时构建 APK、三平台提取器并运行全部测试。

## 参考

- [Profile 结构](docs/kernel_profiles/PROFILE_SCHEMA_ZH.md)与[执行默认值](docs/kernel_profiles/defaults_ZH.md)
- [TimerRoot + vr.ko 设计文档](docs/analysis/timerroot-vr-extract-plan.md)
- [原生核心](src/core/README_ZH.md)、[新增组件](docs/development/adding-a-component_ZH.md)、[工程规范](docs/development/engineering-standards_ZH.md)

## 贡献

- 新内核适配：按[适配指南](docs/kernel_profiles/README_ZH.md)提交 profile PR（模板见 `app/src/main/assets/kernel_profiles/*-template.conf`）。
- 代码改动遵循[工程规范](docs/development/engineering-standards_ZH.md)：先设计后改动，L 级改动需附 `docs/analysis/` 计划文档。

## 来源与许可证

采用 [GNU GPL v3.0](LICENSE)（因移植 [kzktor/ic-timer-lpe](https://github.com/kzktor/ic-timer-lpe) 的符号表格式与 vr.ko 探测逻辑），基于以下项目：

- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)——上游本体（Apache-2.0）
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
- [kzktor/ic-timer-lpe](https://github.com/kzktor/ic-timer-lpe)（GPL-3.0，酷安 @散花神木）——CVE-2026-98260 利用与 ic-syms 契约
- [xxTurborocketxx/TimerRoot](https://github.com/xxTurborrocketxx/TimerRoot)——TimerRoot 前端交互参考
- [hmascs](https://github.com/hmascs)——vivo vr.ko 中和研究（PR #257 vendor_boot 探测）与 [KSuRoot](https://github.com/hmascs/KSuRoot)
- [DONGDERS/Ghostlock-vr](https://github.com/DONGDERS/Ghostlock-vr)——W1c 中和与反汇编推导
- [DONGDERS/DirtyFalg-vr](https://github.com/DONGDERS/DirtyFalg-vr)——vrext 提取器形态参考

第三方组件：[miuix](https://github.com/compose-miuix-ui/miuix)、[Shizuku](https://github.com/RikkaApps/Shizuku)、[Typesafe Config](https://github.com/lightbend/config)、[Apache Commons Compress](https://commons.apache.org/proper/commons-compress/)。
