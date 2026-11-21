# TimerRoot 配置（扩展 ic-syms 表）

TimerRoot 链（CVE-2026-98260）的"profile"是一份文本配置表——**扩展 ic-syms 表**。
它与 Ghostlock 的 HOCON kernel profile 平行：同样支持从全量包 / boot.img /
payload.bin / OTA 链接解析生成、导入现成文件、导出分享。

设计目标：**一份二进制 + 按内核配置**，替代上游"一个内核一个构建"的模式。
APK 内置 CI 构建的 `libtimerroot.so`（`third_party/timerroot`，静态 PIE 可执行
文件，按 jniLib 约定打包），内核相关数字全部在运行时从下表加载；内置的
编译期 profile（PD2571，6.1.145-android14）仅作为没有表时的回退。

## 格式

```text
# ic-timer symbol table
# build=6.1.145-android14-11-maybe-dirty      ← 表来源内核（uname -r）
__tracepoint_sys_exit=0xffffffc00a3c9ec0      ← 符号：name=0x链接期地址
selinux_state=0xffffffc00a55a4f0
init_user_ns=0xffffffc00a1f0f70
init_cred=0xffffffc00a1cae08
root_user=0xffffffc00a1f1208                   （fake-cred 对象，可选）
init_ucounts=0xffffffc00a1f2ab8
init_groups=0xffffffc00a1f2528
...                                            （62 个投票锚点，可选）
# geometry (BTF-derived; consumed by the TimerRoot core)
off.timer_alloc=0x108                          ← 几何：off.<field>=0x值
off.cred_req=0xb8
...
```

- **符号区**：`name=0xADDR`（链接期 kallsyms 地址）。四个目标
  （`__tracepoint_sys_exit` / `selinux_state` / `init_user_ns` / `init_cred`）
  为硬性要求；其余锚点与 fake-cred 对象缺席时在利用侧降级。
- **几何区**：`off.<field>=0xVALUE`。16 个**必需键**（缺失则表驱动运行被拒）：

  `timer_alloc`（sizeof k_itimer）、`cred_req`（sizeof cred）、
  `task_alloc_bytes`（sizeof task_struct）、`task_cred`（task_struct.cred）、
  `cred_uid`、`cap_inh` / `cap_perm` / `cap_eff` / `cap_bset` / `cap_amb`、
  `cred_security`、`cred_user`、`cred_user_ns`、`cred_ucounts`、
  `cred_group_info`、`tp_funcs`（tracepoint.funcs）。

- **可选键**：`cred_alloc`（cred slab 桶大小；缺席时按请求尺寸匹配）、
  `timer_node_off`（k_itimer.node，默认 0x78）、`timer_site_low21` /
  `copy_process_low21`（调用点低 21 位，运行时可自检）、`fullcap`、
  `selinux_blob_off`、`selinux_sid_kernel`。

提取器（`tools/extract_rs`，`--format ic-syms`）从镜像的 kallsyms + BTF
自动生成全部必需键与 `timer_node_off`；`cred_alloc` 故意不输出（slab
桶的填充无法从 BTF 推导，错误的桶会静默漏配，按请求尺寸匹配更稳）。

## 运行时门禁（third_party/timerroot/timer98260.c）

满足以下任一条件才允许运行：

1. `uname -r` 匹配内置编译期 profile（`PROFILE_KERNEL_MATCH`）；或
2. **表驱动**：已暂存表、`# build=` 与 `uname -r` 匹配、且 16 个必需
   几何键齐全；或
3. 显式设置 `IC_ALLOW_ANY_KERNEL=1`（app 内开关；无几何时日志会给出
   盲跑警告）。

关键安全不变量：编译期 profile 与 `uname` 不匹配时 `g_static_ok` 在任何
写入前被清零——KASLR 滑移一律从实测 timer 调用点推导（2 MiB low21
规则），链接地址一律取自表，绝不使用另一镜像的 `STATIC_*` 地址。

## 界面入口

- 主页 **TimerRoot 配置**（链选择器下方，随时可进）；
- 高级选项 → **参数配置** 下方的 **98260 配置**。

二进制来源优先级（`GhostlockUserService.stageTimerRootBinary`）：
导入的二进制 > 内置 `libtimerroot.so` > 遗留 `assets/t98260`（开发用）。

## 契约同步

必需键集合在三处保持镜像，改动时必须同步：

| 位置 | 用途 |
| --- | --- |
| `third_party/timerroot/ic_syms.c`（`ic_geo_keys[]`） | C 侧解析与计数 |
| `tools/extract_rs/src/report.rs`（`collect_ic_geometry`） | 生成侧 |
| `app/src/main/kotlin/.../domain/model/GhostlockModels.kt`（`TimerRootGeometry`） | app 侧校验/展示 |

宿主回归：`third_party/timerroot/tests/geo_test.c`（CI 每次构建运行）。
