package com.ghostlock.app.domain.model

data class CpuPair(val primary: Int, val consumer: Int) {
    override fun toString(): String = "$primary,$consumer"
}

/**
 * Which exploit chain the Run button drives. GHOSTLOCK is the in-tree
 * CVE-2026-43499 native pipeline; TIMER_ROOT shells out to the t98260
 * binary (CVE-2026-98260, kzktor/ic-timer-lpe lineage) through Shizuku.
 */
enum class ExploitChain { GHOSTLOCK, TIMER_ROOT }

/** One candidate library inside a manager APK's lib/arm64-v8a. */
data class KsudLibraryEntry(
    val zipPath: String,
    val sizeBytes: Long,
    /** Our content signature (late-load log line) matched this entry. */
    val detectedKsud: Boolean,
) {
    val fileName: String get() = zipPath.substringAfterLast('/')
}

/** One archived ic-syms table in filesDir/timerroot_tables (98260 加载配置). */
data class TimerRootArchivedTable(
    /** `# build=` banner of the archived table (its kernel). */
    val release: String,
    /** Symbol/geometry stats, same shape as the staged-table banner. */
    val symbols: Int = 0,
    val geometryKeys: Int = 0,
    val geometryEssential: Int = 0,
    /** Stored file name inside the archive directory. */
    val fileName: String,
)

/** TimerRoot chain status shown by the config screen. */
data class TimerRootState(
    val chain: ExploitChain = ExploitChain.GHOSTLOCK,
    /** t98260 available: bundled libtimerroot.so, embedded asset or
     * user-imported binary. */
    val binaryAvailable: Boolean = false,
    val binarySource: TimerRootBinarySource = TimerRootBinarySource.MISSING,
    /** Size of the binary that will run, for the status line. */
    val binarySizeBytes: Long = 0,
    /** ic-syms table staged for this kernel (null = none). */
    val symsRelease: String? = null,
    /** Symbol/geometry stats of the staged table. */
    val symsSymbols: Int = 0,
    val symsGeometryKeys: Int = 0,
    val symsGeometryEssential: Int = 0,
    /** Archived tables the 加载配置 page offers for explicit loading. */
    val tables: List<TimerRootArchivedTable> = emptyList(),
    /** User's explicit libksud.so choice inside the manager APK ("auto" = null). */
    val ksudEntry: String? = null,
    /** IC_ALLOW_ANY_KERNEL=1 for t98260: run an imported binary whose built-in
     * profile does not match this kernel, relying on the staged ic-syms table
     * for the slide. Only meaningful with a staged table. */
    val allowAnyKernel: Boolean = false,
) {
    /** The staged table carries all 16 essential geometry keys, i.e. the
     * generic bundled library can run table-driven on the table's kernel. */
    val symsGeometryComplete: Boolean
        get() = symsGeometryEssential >= TimerRootGeometry.ESSENTIAL_COUNT
}

enum class TimerRootBinarySource { MISSING, BUNDLED, EMBEDDED, IMPORTED }

/** Geometry key set of the extended ic-syms table (the "98260 配置").
 * Mirrors ic_geo_keys[] in third_party/timerroot/ic_syms.c
 * (IC_GEOM_ESSENTIAL = 16) and collect_ic_geometry in
 * tools/extract_rs/src/report.rs. */
object TimerRootGeometry {
    const val ESSENTIAL_COUNT = 16

    val ESSENTIAL_KEYS: Set<String> = setOf(
        "timer_alloc",
        "cred_req",
        "task_alloc_bytes",
        "task_cred",
        "cred_uid",
        "cap_inh",
        "cap_perm",
        "cap_eff",
        "cap_bset",
        "cap_amb",
        "cred_security",
        "cred_user",
        "cred_user_ns",
        "cred_ucounts",
        "cred_group_info",
        "tp_funcs",
    )

    /** Essential + optional refinements the C loader recognizes. */
    val KNOWN_KEYS: Set<String> = ESSENTIAL_KEYS + setOf(
        "cred_alloc",
        "timer_node_off",
        "timer_site_low21",
        "copy_process_low21",
        "fullcap",
        "selinux_blob_off",
        "selinux_sid_kernel",
    )
}

data class KernelSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String = "",
    val kernelSupported: Boolean,
    val cpuPairs: List<CpuPair>,
    val cpuPairLabels: List<String>,
    val selectedCpuPair: Int,
    val safeModeEnabled: Boolean,
    /** Skip the pre-attack KernelSU check and run the exploit as a test. */
    val forceAttackTest: Boolean = false,
    /** Profile/imported offsets force the Shizuku path. */
    val recommendShizuku: Boolean,
    /** User-selected Shizuku path for kernels that do not require it. */
    val shizukuEnabled: Boolean = false,
    val shizukuStatus: ShizukuStatus,
)

enum class ShizukuStatus { NOT_REQUIRED, NOT_RUNNING, PERMISSION_REQUIRED, READY }

enum class LogTone { Default, Error, Success, Warning, Progress, Kotlin, Shizuku }

data class LogEntry(val text: String, val tone: LogTone)

data class OffsetCandidate(val release: String, val document: String)

/** One verbatim user-imported document in the user profile folder. */
data class UserProfileFile(
    val name: String,
    val releases: List<String>,
    val importedAt: Long,
    val sizeBytes: Long,
    val parseError: Boolean,
    /** 1 = legacy layout (load only), 2 = current layout (editable). */
    val version: Int = 2,
)

/** One editable advisory execution value (PROFILE-SUGGEST-01 / profile-ui). */
data class ExecutionFieldValue(
    val path: String,
    val value: Long,
    val overridden: Boolean,
)

/** Debug-only export preferences shown by the hidden debug screen. */
data class DebugSettings(
    val exportEnabled: Boolean = true,
    val exportLocation: String = "Download/ghostlock-debug-log",
    val kernelLogEnabled: Boolean = true,
)

/** One node of the resolved profile tree: a JSON group or a numeric leaf. */
data class ProfileFieldNode(
    val path: String,
    val name: String,
    val value: Long? = null,
    /** True when this field or any descendant has an explicit override. */
    val overridden: Boolean = false,
    val children: List<ProfileFieldNode> = emptyList(),
) {
    val isGroup: Boolean get() = children.isNotEmpty()
}

/** Resolved execution view for the advanced editor (controller-owned). */
data class ProfileConfig(
    val release: String,
    val hasProfile: Boolean,
    /** Hierarchical view of every numeric leaf, override flags included. */
    val roots: List<ProfileFieldNode> = emptyList(),
    /** General (execution tuning) subset exposed by the parameters screen. */
    val general: List<ExecutionFieldValue> = emptyList(),
    /** Explicit route from the profile; null means geometry inference. */
    val route: String? = null,
    /** Declared fallback route ("none"/"<route>"); null means unset. */
    val fallbackTo: String? = null,
    /** Dotted paths whose resolved value violates the geometry rules. */
    val invalidPaths: Set<String> = emptySet(),
) {
    companion object {
        /** Routes a profile may declare ("" is the inference fallback). */
        val Routes = listOf("tcp_zerocopy", "select_stack", "multicast_waiter")

        /**
         * Route-independent execution tuning paths the general editor always
         * exposes. Route-specific tuning is appended dynamically from the
         * resolved profile for the active route (plus its fallback), so a
         * profile never shows another route's knobs.
         */
        val GeneralPaths = listOf(
            "execution.selected_cpus.main",
            "execution.selected_cpus.consumer",
            "execution.heap.prepare_max_attempts",
            "execution.heap.prepare_timeout_ms",
            "execution.heap.kernelsnitch_timeout_ms",
            "execution.race.route_wait_ms",
            "execution.race.route_done_timeout_ms",
            "execution.race.setup_settle_us",
            "execution.race.state_poll_interval_us",
            "execution.stages.w1_attempts",
            "execution.stages.w1_settle_us",
            "execution.stages.w1_scratch_repair_attempts",
            "execution.stages.w2_attempts",
            "execution.stages.w2_settle_us",
            "execution.stages.w3_chain_rounds",
            "execution.stages.w3_attempts",
            "execution.stages.w3_settle_us",
            "execution.handoff.pre_dispatch_settle_ms",
            "execution.handoff.module_poll_attempts",
            "execution.handoff.module_poll_interval_ms",
            "execution.handoff.enforce_poll_attempts",
            "execution.handoff.enforce_poll_interval_ms",
        )
    }
}

data class KernelOffsets(
    val release: String,
    val scalars: Map<String, Long?>,
    val symbols: Map<String, Long?>,
    val structFields: Map<String, Long?>,
)

sealed interface OffsetImportResult {
    data class Imported(val releases: List<String>) : OffsetImportResult
    data class RequiresOverwrite(val releases: List<String>) : OffsetImportResult
    data object AlreadyPresent : OffsetImportResult
    data class MissingIncludes(val files: List<String>) : OffsetImportResult
    data class Failed(val reason: String) : OffsetImportResult
}

sealed interface ParseResult {
    /** Fields only an xbl_config/uefi sidecar can supply (e.g.
     * `kernel_phys_load`) that the parsed profile is still missing. */
    data class Parsed(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
        /** Name of the stored document, so the caller can auto-load it. */
        val documentName: String? = null,
    ) : ParseResult

    data class RequiresOverwrite(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
    ) : ParseResult

    data object AlreadyPresent : ParseResult

    data class Failed(val code: Int, val reason: String? = null) : ParseResult
}

/**
 * Input of the TimerRoot (CVE-2026-98260) ic-syms parse. Mirrors the
 * GhostLock parse sources: a remote full-package link, a local OTA zip /
 * payload.bin document, or an already-staged boot image with optional
 * attached sidecar images.
 */
sealed interface TimerRootSymsSource {
    /** Remote OTA zip / payload.bin link; partitions are range-extracted. */
    data class Url(val url: String) : TimerRootSymsSource

    /**
     * Local OTA zip or payload.bin document (SAF uri). The package is read
     * in place through a seekable descriptor — a full package is never
     * copied into app storage first — and boot / xbl_config / uefi /
     * vendor_boot are extracted straight from it.
     */
    data class Package(val uri: String) : TimerRootSymsSource

    /**
     * A cached boot image (bare boot.img has no partitions to extract);
     * xbl_config / uefi derive the physical base, vendor_boot feeds the
     * runtime vr.ko probe on vivo/iQOO.
     */
    data class BootImage(
        val path: String,
        val xblConfigPath: String? = null,
        val uefiPath: String? = null,
        val vendorBootPath: String? = null,
    ) : TimerRootSymsSource
}
