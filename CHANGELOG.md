# Changelog — Ghostlock Vivo

vivo/iQOO 适配 fork of [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
(上游已移交 [LSPosed/LSPrivilege](https://github.com/LSPosed/LSPrivilege)；本 fork 保持
`Ghostlock Vivo` 名称与 `io.github.masgzy.ghostlock.vivo` 包名，不跟随改名)。

## Unreleased

### Synced from upstream (LSPosed/LSPrivilege, fork point 6641116 → d1dbb2d)

- **APatch 管理器支持**（上游 #988 全量移植，含我方仓库冲突的手工合并）：
  - 管理器扫描/交接识别 `libapd.so`（`me.bmax.apatch`），`/proc/modules` 同时观察
    `kernelsu` 与 `kernelpatch`，root 探针追加 `kp -c`；
  - 根脚本按守护进程切换 `[ksu]`/`[apd]` 日志标签，`apd` late-load 免 `--kmi` 参数；
  - **TimerRoot 链同步接入 APatch**：`runTimerRoot` AIDL 增加 `managerPackage` 参数，
    shell 侧 `stageKsud` 改走 `ManagerScanner.resolveDaemonBinary`（此前只认
    `libksud.so`，装了 APatch 的设备 98260 交接会静默缺守护进程）；
  - **FolkPatch（APatch 分叉）零核心适配**：两版发布包名 `me.yuki.folk`（LyraVoid）与
    `folk.zakodan`（第三方重打包）继续打包 `libapd.so`、内核模块同为 `kernelpatch`，
    只需把包名加进 `BUILTIN` 扫描列表即被自动识别。
- **victim 校验管道 3 秒 poll 超时**（上游 #993）：vivo `vr.ko` tagB 场景下子进程僵尸化
  会让 uid 管道永远静默，旧的阻塞 read 直接挂死整轮攻击；三处校验读全部带界。
- **内核 profile 新增**（上游 4 提交）：OPPO A78 5G 新 OTA（6.6.118）、Sharp AQUOS
  sense10 SH-M33（6.1.157）、Xiaomi MIX Fold 3（5.15.178/5.15.194）、Honor 400
  DNY-NX9（Android 16，5.15.180）。

### Fork identity

- **应用改名 Ghostlock Vivo**，包名迁至 `io.github.masgzy.ghostlock.vivo`
  （app/profile-core 源码树、AIDL 包路径、vendored zstd Java 包、proguard、CI 产物名
  `GhostlockVivo-release.apk` 同步迁移；安装即新身份，旧 `com.ghostlock.app` 数据不迁移）。
- 按用户决定**不跟随上游改名 LSPrivilege**；文档/关于页链接指向本仓库 docs。

### Fixes & improvements (fork)

- **98260 执行门控**：TimerRoot 链下 Shizuku 未就绪时运行按钮直接置灰（点按浮层打开
  98260 配置页说明原因），不再进入 runner 内部才报错；GhostLock 链保持原门控。
- **W3 seccomp 清除成功率**：
  - slab 清理从「仅第一轮尝试」改为每轮尝试前都清（沿用 W2+W3 链轮首的清理节奏，
    上轮失败喷射的页不再堆积在 slab 里拉低下一轮命中率）；
  - leaf 方向探测尝试 4 → 6 次（探测失败代价是整轮 victim 重来，探测本身很便宜）。
- **远程全量包分块读取重试**：`HttpRangeReader.read` 单次范围请求对瞬时失败
  （超时/连接中断/短读/CDN 5xx）带指数退避重试（4 次，500ms 起）；8 GiB 包数百次
  分块请求中任何一次抖动不再中止整个解析。Range 头被服务端忽略（200 应答）仍快速失败。
- **测试同步**：`remote-main-6x-offsets.json` fixture 补齐 Sharp AQUOS sense10 与
  OPPO A78 新 OTA 两条（由 conf 直接生成，等价性测试 70 → 72 条全绿）；
  `ManagerScannerTest` 覆盖 FolkPatch 包名。
- 文档链接（MediaTek 取值文档、profile schema）指向本仓库。

## 2026-11-22 (b2532ab)

- CI 修复：Robolectric android-all jar 改走 Gradle 解析 + 阿里云镜像，依赖传输 429
  指数退避（`455e159` + `b2532ab`，此后 CI 全绿）。
- REPLACE_ZSTD 解码 NoSuchFieldError 修复：aircompressor 2.0.2 vendored 进
  `data/ota/zstd/`，`sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET` 静态字段读改为
  `Unsafe.arrayBaseOffset(byte[].class)`（新 ART 已移除该字段）；测试侧用未修补版
  压缩、真机侧用修补版解码，同一份实现。
- 98260 假成功修复：vendor 预检（`t98260 info` 静默即不兼容构建）+ 结果判定改为
  要求 `[+] root confirmed` / `[+] fake chain complete` 标记，exit 0 不再误报完成。
- 98260 shell 侧导入二进制压过内置库修复：导入移除时同步清除 shell 侧副本，运行前
  reconcile（`clearTimerRootBinary`）。
- 98260 配置多级菜单、链感知状态框、ic-syms 表归档/指定加载/导出（对齐 GhostLock
  的参数配置/加载配置页）。
- 远程全量包解析 OOM 闪退修复：`RangeChunkStream` 2 MiB 分块流式解码（ZSTD/BZ2 直流），
  XZ 走缓冲路径（≤768 MiB 上限）；本地包经 SAF `LocalFileRangeReader` 原地解析，8 GiB
  包不再整包拷入 filesDir。
- vendor_boot.img 导入与循环式附加镜像流程（vivo/iQOO vr.ko 偏移探测）。

## 前情（2026-11-21 及更早）

- vivo 双链：Ghostlock（CVE-2026-43499）+ TimerRoot（CVE-2026-98260，经 Shizuku
  shell 域运行 t98260）。
- W1c `__tracepoint_sys_exit` 探针全局解除、W2b 每任务标签清除（标签偏移从
  vendor_boot 的 `vr.ko` 实时探测）。
- ic-syms 符号表解析（boot.img / OTA ZIP / URL → t98260 需要的表）。
- SukiSU Nova 随机 `lib<random>.so` 内容签名检测。
- 解析值规范化 + 解析漏斗 catch Throwable（OOM 是 Error 不再杀进程）。
