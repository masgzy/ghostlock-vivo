# TODO — Ghostlock Vivo

按优先级排序；完成项移到底部归档。

## 高优先

- [ ] **98260 真机回归**（Shizuku 链全流程）：内置 6.1.145 表 + 用户导入表两条路径都跑一遍，确认
  `[+] fake chain complete` 判定、APatch/FolkPatch 管理器交接（`stageKsud` 新路径）与
  Shizuku 未就绪置灰按钮的表现。11-28 第二轮真机（PD2352C 16.2.17.0）已确认：泄漏窗口
  修复生效（hello 到达、exec 分配入窗），直方图给出根因——表 `off.cred_req=0xb0`（BTF
  sizeof）而运行时 cred 是 `0xb8/0xc0 x2`（cred_jar SLAB 合并后报合并 cache 的
  object_size）；已加运行时签名自愈（唯一 count==2 cred 对自动采用 + 原地重扫）。下一轮
  真机关注：`[cred] adopting runtime signature req=0xb8` 是否出现、R 是否拿到、后续
  selinux/fake_cred plant 阶段 `calibrate_base` 的对齐偏好是否每轮都给出
  `0xffffff7f80000000`。
- [ ] **cred_req 无法静态预知**：`off.cred_req` 来自 BTF `sizeof(struct cred)`，但
  SLAB 合并使运行时 bytes_req 可能不同（PD2352C：0xb0 → 0xb8）。运行时自愈已兜底；
  如上游/社区发现更多机型样本，考虑把 cred 尺寸区间发现也反馈进表（`off.cred_req_hint`）
  或在文档标注该字段「尽力而为」。
- [ ] **TimerRoot 链 `[site] ... differs from profile` 后的表校验**：运行时探测到的
  do_timer_create 调用点（如 PD2352C 16.2.17.0 的 `0x1a2c34`）与编译 profile 不同属正常，
  但当前几何块不携带 `off.timer_site_low21`/`off.copy_process_low21`，无法在运行前把
  "表与内核是否同源"校验到调用点级别；可让 Rust 提取器（`tools/extract_rs/src/derive.rs`
  已有 disasm 能力）把两值写进表并在 `info` 预检时对比告警。
- [ ] **Ghostlock 链真机回归**（CVE-2026-43499）：W1→W2→W3 全链 + KSU/APatch late-load，
  重点验证 W3 每轮 slab 清理与 leaf 探测 6 次改动的成功率变化（vivo/iQOO 设备）。
  11-28 日志里 Ghostlock 解析段 `pselect_waiter_shift derivation failed: ... -216`
  走了 family 默认值（`pselect_waiter_shift=1`），需在真机上确认该默认值对 PD2352C 成立。
- [ ] **CI 观察一轮**：APatch 移植改动较大（原生 + Kotlin），等 Actions 全绿后发 pre-release。
- [ ] **REPLACE_XZ 流式化**：`XzDecoder` 目前整输入整输出驻留（768 MiB 输入上限 + 全量
  解压缓冲），大分区（非 vivo 的 vendor_boot/system 逐块 XZ）有 OOM 风险。改用
  commons-compress `XZCompressorInputStream` 流式路径可同时删掉 `XZ_INPUT_LIMIT` 特判。
  （vivo 全量包实际用 ZSTD，故不阻塞。）

## 中优先

- [ ] **归档表删除入口**：98260「已保存的表」只能追加不能删除，长期使用会无限增长；
  需要列表项长按删除 + 确认弹窗。
- [ ] **`/data/local/tmp/ksud` 固定名收窄**：shell 侧 `stageKsud` 把守护进程写到固定路径，
  并发运行或上次残留可能串台；改为 `ghostlock-ksud-<pid>` 临时名 + 运行后清理
  （注意 root 子进程的可见性约束）。
- [ ] **`importTimerRootTable` / `stageTimerRootTable` 并发保护**：两者都用
  `ic-syms.txt.partial` 固定名，导入与指定加载同时进行会互相覆盖；改唯一临时名。
- [ ] **seccomp 探针误判反馈**：W3 探针把 EPERM/ENOSYS 视为过滤未清除，但 vivo LSM 也可能
  直接回 EPERM；把探针 errno 分类打进日志（区分 RET_ERRNO 与真实内核拒绝），便于
  profile 调参。
- [ ] **profile 携带 W3 每轮清理开关**：新加的每轮 slab 清理对部分机型可能反而降低复用
  命中率（如 slab 已被 prebuilt 占住）；观察真机数据，必要时加 profile 开关。
- [ ] **上游持续同步**：上游已改名 LSPrivilege 并继续加 profile/修复；定期
  `git fetch upstream`，跳过 rename 提交（75bb6b3 类），其余 cherry-pick。

## 低优先

- [ ] **fixture 生成器脚本化**：`remote-main-6x-offsets.json` 目前靠手写脚本从 conf 生成
  （本次补 AQUOS/A78 时用的是一次性脚本）；落成 `tools/gen_legacy_fixture.py` 固化。
- [ ] **Telegram 发布脚本文案**：`post_telegram.sh` 里 APK 描述仍写 "GhostLock"，与新
  应用名 Ghostlock Vivo 统一。
- [ ] **98260 配置页与 GhostLock 配置页的布局统一**：两页间距/分组仍有细微差异。
- [ ] **AR/ES/pt-BR 上游翻译回迁**：上游新增了三语翻译（fork 点之前），ForkPatch/
  Ghostlock Vivo 专属字符串需要补翻。

## 已完成（归档）

- [x] 2026-11-28 真机日志回归：98260 cred 泄漏窗口改等 hello、重复绑定/残留运行标记/t98260
      原子 stage、vendor_boot.img 自拷贝误删、ksud late-load 参数与管理器拉起交回 App
- [x] 2026-11-27 上游同步（victim 3s 超时、APatch 支持、4 组 profile），ForkPatch 零适配确认
- [x] 2026-11-27 包名 `io.github.masgzy.ghostlock.vivo` + 应用名 Ghostlock Vivo
- [x] 2026-11-27 98260 无 Shizuku 置灰 + TimerRoot ksud 解析覆盖 APatch/FolkPatch
- [x] 2026-11-27 W3 每轮 slab 清理 + leaf 探测 6 次 + 范围读取重试
- [x] 2026-11-22 ZSTD vendored 修补、98260 假成功、CI 全绿（b2532ab）
