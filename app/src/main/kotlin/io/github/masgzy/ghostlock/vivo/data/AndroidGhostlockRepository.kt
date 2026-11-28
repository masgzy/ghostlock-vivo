package io.github.masgzy.ghostlock.vivo.data

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.core.content.edit
import androidx.core.net.toUri
import io.github.masgzy.ghostlock.vivo.BuildConfig
import io.github.masgzy.ghostlock.vivo.BuildInfo
import io.github.masgzy.ghostlock.vivo.data.ManagerScanner
import io.github.masgzy.ghostlock.vivo.domain.model.CpuPair
import io.github.masgzy.ghostlock.vivo.domain.model.DebugSettings
import io.github.masgzy.ghostlock.vivo.domain.model.ExploitChain
import io.github.masgzy.ghostlock.vivo.domain.model.KsudLibraryEntry
import io.github.masgzy.ghostlock.vivo.domain.model.TimerRootArchivedTable
import io.github.masgzy.ghostlock.vivo.domain.model.TimerRootBinarySource
import io.github.masgzy.ghostlock.vivo.domain.model.TimerRootState
import io.github.masgzy.ghostlock.vivo.domain.model.KernelSnapshot
import io.github.masgzy.ghostlock.vivo.domain.model.OffsetCandidate
import io.github.masgzy.ghostlock.vivo.data.ota.HttpRangeReader
import io.github.masgzy.ghostlock.vivo.data.ota.LocalFileRangeReader
import io.github.masgzy.ghostlock.vivo.data.ota.OtaPayloadExtractor
import io.github.masgzy.ghostlock.vivo.domain.model.OffsetImportResult
import io.github.masgzy.ghostlock.vivo.domain.model.ParseResult
import io.github.masgzy.ghostlock.vivo.domain.model.ProfileConfig
import io.github.masgzy.ghostlock.vivo.domain.model.TimerRootSymsSource
import io.github.masgzy.ghostlock.vivo.domain.model.UserProfileFile
import io.github.masgzy.ghostlock.vivo.domain.repository.GhostlockRepository
import io.github.masgzy.ghostlock.vivo.domain.repository.ProfileConfigController
import io.github.masgzy.ghostlock.vivo.shizuku.ShizukuExploitRunner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Android implementation of the domain repository. All platform I/O lives here. */
class AndroidGhostlockRepository(context: Context) : GhostlockRepository {
    private companion object {
        const val OffsetsFileName = "offsets.conf"
        const val LegacyOffsetsFileName = "offsets.json"

        /** Staged image names: the native runtime reads these under
         * GHOSTLOCK_HOME (= the app files dir). */
        const val VendorBootFileName = "vendor_boot.img"
        const val UefiFileName = "uefi.img"

        /** A vendor_boot image is the only thing allowed under that name. */
        const val VendorBootMagic = "VNDRBOOT"

        /**
         * Reads exactly [size] bytes, or null when the stream is shorter.
         *
         * A single `read()` is not guaranteed to fill the buffer — a
         * ContentResolver or FileInputStream stream can return a short count
         * on the first call — so checking one read's return value against the
         * buffer size would reject perfectly valid images at random.
         */
        fun readExactHeader(stream: java.io.InputStream, size: Int): ByteArray? {
            val header = ByteArray(size)
            var filled = 0
            while (filled < size) {
                val read = stream.read(header, filled, size - filled)
                if (read <= 0) return null
                filled += read
            }
            return header
        }

        const val UserProfilesDirectoryName = "user_profiles"
        const val EditSessionPreferences = "ghostlock_edit_session"
        const val ExtractBinaryName = "libextract.so"
        const val DefaultDebugLocation = "Download/ghostlock-debug-log"
        const val PrefForceAttackTest = "force_attack_test"
        const val PrefDebugExportEnabled = "debug_export_enabled"
        const val PrefDebugExportLocation = "debug_export_location"
        const val PrefDebugKernelLogEnabled = "debug_kernel_log_enabled"
        const val PrefDebugProfileOverrides = "debug_profile_overrides"

        /* U01-S14: per-run KernelSU log name; the resolved path travels to
         * the native process via GHOSTLOCK_KSU_LOG. */
        fun ksuLogName(runStamp: Long) = "ghostlock-ksu-$runStamp.log"

        /* Every run's stdout/stderr is redirected here (export or not), so the
         * previous run can be inspected on the next start-up. */
        const val NativeLogFileName = ".ghostlock_native.log"

        /* Attack step status persisted by the app. The native process reports
         * each step on stdout and waits for an ACK on stdin; the app owns the
         * file so a kernel panic still leaves the last in_progress step for the
         * next launch to read. HOCON/JSON. */
        const val RunStateFileName = ".ghostlock_run_state.json"
        const val PREF_EXPLOIT_CHAIN = "exploit_chain"
        const val PREF_KSUD_ENTRY = "ksud_library_entry"
        const val PrefTimerRootAllowAnyKernel = "timerroot_allow_any_kernel"
        const val PrefLaunchManagerOnSuccess = "launch_manager_on_success"
        const val TIMER_ROOT_BINARY = "t98260.bin"
        const val TIMER_ROOT_SYMS = "ic-syms.txt"
        /** Archive of every parsed/imported ic-syms table, the 98260 chain's
         * equivalent of the GhostLock saved-profile list. */
        const val TimerRootTablesDirectoryName = "timerroot_tables"

        /* Parsed-profile normalization (see canonicalizeParsedEntries): the
         * extractor measures some sections per image, others it cannot derive
         * at all. When the parsed release has a bundled twin, the sections the
         * extractor cannot measure come from the twin wholesale, the measured
         * ones keep the parsed values (builtin as the base layer), and flags
         * follow the twin — otherwise a stored "copy_size = 136"-style
         * half-truth would override the verified builtin at merge time. */
        val parsedAuthoritativeSections = setOf("offset", "task_struct")
        val bundledAuthoritativeSections = setOf(
            "execution", "route", "fallback", "cred", "kernelsnitch", "vr_guard",
        )
        val bundledAuthoritativeFlags = setOf(
            "recommend_shizuku", "recommend_vr_guard", "kernel_major", "schema_version",
        )
        /** The CI-built generic 98260 core, packaged as a jniLib (the file
         * is a static PIE executable; the name only makes the APK installer
         * extract it). Staged to /data/local/tmp by the Shizuku runner. */
        const val TIMER_ROOT_LIBRARY = "libtimerroot.so"
        /* An ic-syms table is a few tens of KiB of text; anything larger is a
         * picked image and must go through the extractor. 2 MiB leaves room
         * for verbose per-build tables. */
        const val MAX_SYMS_IMPORT_BYTES = 2L * 1024 * 1024
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"
    }

    private val appContext = context.applicationContext
    private val filesDir: File = appContext.filesDir
    private val preferences get() =
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val offsetsFile get() = File(filesDir, OffsetsFileName)
    /** Archive directory of parsed/imported ic-syms tables (98260 chain). */
    private val timerRootTablesDir get() = File(filesDir, TimerRootTablesDirectoryName)
    private val builtinProfiles = BuiltinProfileCatalog(appContext)
    private val assetConfigLoader = AssetConfigLoader(appContext)
    private val userProfileStore = UserProfileStore(
        directory = File(filesDir, UserProfilesDirectoryName),
        assetLoader = assetConfigLoader,
    )
    private val profileController = AndroidProfileConfigController(
        appContext,
        filesDir,
        userProfileStore,
        preferences,
    )
    private val cpuPairs = mutableListOf<CpuPair>()
    private val cpuPairLabels = mutableListOf<String>()
    private var selectedCpuPair = 0
    private var safeModeEnabled = false
    private var forceAttackTest = false
    private var shizukuEnabled = false
    /** True once the user flipped the toggle; only then does it override the
     * profile suggestion (PROFILE-SUGGEST-01). */
    private var shizukuPreferenceSet = false
    private var pendingParsedDocument: PendingParsedDocument? = null
    private val shizukuRunner = ShizukuExploitRunner(appContext)

    init {
        buildCpuPairs()
        restoreCpuPair()
        restoreShizukuPreference()
        restoreForceAttackTest()
        dropLegacyOffsetsCache()
        migrateLegacyOffsetsStore()
    }

    /** The old JSON offsets cache is not compatible and is discarded. */
    private fun dropLegacyOffsetsCache() {
        runCatching { File(filesDir, LegacyOffsetsFileName).delete() }
    }

    /**
     * Old builds kept imported offsets and parameter overrides in one HOCON
     * file. Split it: overrides move to preferences, the remaining entries
     * become verbatim user documents, then the legacy file is dropped.
     */
    private fun migrateLegacyOffsetsStore() {
        if (!offsetsFile.isFile) return
        runCatching {
            val entries = parseEntries(offsetsFile.readText()) ?: return@runCatching
            for (raw in entries) {
                val entry = raw.asValueMap() ?: continue
                val release = (entry["release"] as? String).orEmpty()
                if (release.isEmpty()) continue
                val overrides = valueMapOf()
                (entry.remove("execution") as? Map<*, *>)?.let { overrides["execution"] = it }
                (entry.remove("route") as? Map<*, *>)?.let { overrides["route"] = it }
                (entry.remove("fallback") as? Map<*, *>)?.let { overrides["fallback"] = it }
                if (overrides.isNotEmpty()) mergeLegacyOverrides(release, overrides)
                if (entry.size > 1) {
                    userProfileStore.save("$release.conf", HoconSupport.render(entry))
                }
            }
            offsetsFile.delete()
        }.onFailure {
            android.util.Log.e("GhostLock", "legacy offsets migration failed", it)
        }
    }

    private fun mergeLegacyOverrides(release: String, overrides: ValueMap) {
        val raw = preferences.getString(PrefDebugProfileOverrides, null)
        val all = runCatching { HoconSupport.parseValue(raw ?: "") }
            .getOrNull().asValueMap() ?: valueMapOf()
        deepMergeValues(all.mutableChild(release), overrides)
        preferences.edit { putString(PrefDebugProfileOverrides, HoconSupport.render(all)) }
    }

    override suspend fun snapshot(): KernelSnapshot {
        val release = System.getProperty("os.version", "unknown").orEmpty()
        /* PROFILE-SUGGEST-01: recommend_shizuku is a suggestion. It seeds the
         * toggle until the user makes an explicit choice, which then overrides
         * it in both directions. */
        val recommendShizuku = release in builtinProfiles.recommendShizuku ||
            importedOffsetsRecommendShizuku(release)
        val shizukuActive = if (shizukuPreferenceSet) shizukuEnabled else recommendShizuku
        return KernelSnapshot(
            deviceName = resolveDeviceName(),
            kernelRelease = release,
            socName = resolveSocName(),
            kernelSupported = isKernelSupported(),
            cpuPairs = cpuPairs.toList(),
            cpuPairLabels = cpuPairLabels.toList(),
            selectedCpuPair = selectedCpuPair,
            safeModeEnabled = safeModeEnabled,
            forceAttackTest = forceAttackTest,
            recommendShizuku = recommendShizuku,
            shizukuEnabled = shizukuActive,
            shizukuStatus = if (shizukuActive) shizukuRunner.status()
            else io.github.masgzy.ghostlock.vivo.domain.model.ShizukuStatus.NOT_REQUIRED,
        )
    }

    override fun selectCpuPair(index: Int) {
        if (index !in cpuPairs.indices) return
        selectedCpuPair = index
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).edit {
                putString("cpu_pair", cpuPairs[index].toString())
            }
    }

    override fun setSafeModeEnabled(enabled: Boolean) {
        safeModeEnabled = enabled
    }

    override fun setForceAttackTest(enabled: Boolean) {
        forceAttackTest = enabled
        preferences.edit { putBoolean(PrefForceAttackTest, enabled) }
    }

    override fun setShizukuEnabled(enabled: Boolean) {
        shizukuEnabled = enabled
        shizukuPreferenceSet = true
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            .edit {
                putBoolean("shizuku_enabled", enabled)
                putBoolean("shizuku_explicit", true)
            }
        if (enabled) shizukuRunner.requestPermission()
    }

    override fun selectedManagerPackage(): String? =
        preferences.getString(ManagerScanner.PREF_KEY, null)?.takeIf { it.isNotBlank() }

    override fun setSelectedManagerPackage(pkg: String?) {
        preferences.edit { putString(ManagerScanner.PREF_KEY, pkg) }
    }

    override fun exploitChain(): ExploitChain =
        if (preferences.getString(PREF_EXPLOIT_CHAIN, null) == ExploitChain.TIMER_ROOT.name) {
            ExploitChain.TIMER_ROOT
        } else {
            ExploitChain.GHOSTLOCK
        }

    override fun setExploitChain(chain: ExploitChain) {
        preferences.edit { putString(PREF_EXPLOIT_CHAIN, chain.name) }
    }

    override fun ksudLibraryChoice(): String? =
        preferences.getString(PREF_KSUD_ENTRY, null)?.takeIf { it.isNotBlank() }

    override fun setKsudLibraryChoice(entry: String?) {
        preferences.edit {
            if (entry.isNullOrBlank()) remove(PREF_KSUD_ENTRY) else putString(PREF_KSUD_ENTRY, entry)
        }
    }

    override suspend fun managerApkPath(): String? = withContext(Dispatchers.IO) {
        val pm = appContext.packageManager
        val chosen = selectedManagerPackage()
        val candidates = if (chosen.isNullOrBlank()) {
            ManagerScanner.resolvePackages(null)
        } else {
            listOf(chosen) + ManagerScanner.resolvePackages(null).filter { it != chosen }
        }
        candidates.firstNotNullOfOrNull { pkg ->
            runCatching { pm.getApplicationInfo(pkg, 0).sourceDir }
                .getOrNull()
                ?.takeIf { File(it).isFile }
        }
    }

    override suspend fun listKsudLibraries(): List<KsudLibraryEntry> =
        withContext(Dispatchers.IO) {
            val apk = managerApkPath() ?: return@withContext emptyList()
            runCatching { ManagerScanner.listApkLibraries(apk) }.getOrDefault(emptyList())
        }

    override suspend fun timerRootState(): TimerRootState = withContext(Dispatchers.IO) {
        val imported = File(filesDir, TIMER_ROOT_BINARY).takeIf { it.isFile && it.length() > 0 }
        val bundled = File(appContext.applicationInfo.nativeLibraryDir, TIMER_ROOT_LIBRARY)
            .takeIf { it.isFile && it.length() > 0 }
        val embedded = runCatching {
            appContext.assets.open("t98260").use { it.readBytes().size }
        }.getOrDefault(0) > 0
        /* Same precedence as GhostlockUserService.stageTimerRootBinary: an
         * explicit import wins, then the CI-built generic library, then the
         * legacy dev asset. */
        val (source, size) = when {
            imported != null -> TimerRootBinarySource.IMPORTED to imported.length()
            bundled != null -> TimerRootBinarySource.BUNDLED to bundled.length()
            embedded -> TimerRootBinarySource.EMBEDDED to 0L
            else -> TimerRootBinarySource.MISSING to 0L
        }
        val syms = File(filesDir, TIMER_ROOT_SYMS)
        val summary = if (syms.isFile) {
            runCatching { TimerRootTable.summarize(syms.readText()) }.getOrNull()
        } else {
            null
        }
        TimerRootState(
            chain = exploitChain(),
            binaryAvailable = source != TimerRootBinarySource.MISSING,
            binarySource = source,
            binarySizeBytes = size,
            symsRelease = summary?.release,
            symsSymbols = summary?.symbols ?: 0,
            symsGeometryKeys = summary?.geometryKeys ?: 0,
            symsGeometryEssential = summary?.geometryEssential ?: 0,
            tables = listTimerRootTables(),
            ksudEntry = ksudLibraryChoice(),
            allowAnyKernel = timerRootAllowAnyKernel(),
        )
    }

    override suspend fun importTimerRootBinary(uri: String): String? = withContext(Dispatchers.IO) {
        val target = File(filesDir, TIMER_ROOT_BINARY)
        appContext.contentResolver.openInputStream(uri.toUri())?.use { input ->
            FileOutputStream(target).use { output -> input.copyTo(output) }
        } ?: throw IOException("cannot open $uri")
        if (target.length() < 1024) {
            target.delete()
            throw IOException("file too small to be the t98260 exploit")
        }
        TIMER_ROOT_BINARY
    }

    override suspend fun removeTimerRootBinary() {
        withContext(Dispatchers.IO) {
            File(filesDir, TIMER_ROOT_BINARY).delete()
            /* The shell-side copy outlives the app-side import: staging
             * prefers it, so it must die too or a long-removed import keeps
             * winning every run while the config screen says "bundled".
             * Best effort (needs a live Shizuku); every run without a local
             * import reconciles the same way. */
            runCatching { shizukuRunner.clearTimerRootBinary { } }
        }
    }

    /**
     * Runs the extractor with `--format ic-syms` against the same input
     * universe as parseSource (boot.img / payload.bin / local OTA zip / URL)
     * and stages the result as the TimerRoot table. The output carries the
     * BTF geometry block when the image has BTF.
     *
     * A package source (local OTA zip / payload.bin / URL) is decoded by the
     * pure-Kotlin extractor — boot, xbl_config, uefi and vendor_boot come
     * straight out of the package, no attach step — and local packages are
     * read in place through a seekable descriptor, so an 8 GiB full package
     * is never copied into app storage first. A bare boot image goes to the
     * native extractor with whatever was attached in the attach loop.
     */
    override suspend fun parseTimerRootSyms(
        input: TimerRootSymsSource,
        onLog: (String) -> Unit,
    ): ParseResult = withContext(Dispatchers.IO) {
        val binary = File(appContext.applicationInfo.nativeLibraryDir, ExtractBinaryName)
        if (!binary.isFile) {
            return@withContext ParseResult.Failed(1, "missing native binary: ${binary.absolutePath}")
        }
        return@withContext try {
            val out = File(filesDir, TIMER_ROOT_SYMS)
            var tempBoot: File? = null
            var tempXbl: File? = null
            var tempUefi: File? = null
            var tempVendorBoot: File? = null
            var localReader: LocalFileRangeReader? = null
            try {
                var bootPath: String
                var xblPath: String? = null
                var uefiPath: String? = null
                var vendorBootPath: String? = null
                when (input) {
                    is TimerRootSymsSource.BootImage -> {
                        bootPath = input.path
                        xblPath = input.xblConfigPath
                        uefiPath = input.uefiPath
                        vendorBootPath = input.vendorBootPath
                    }

                    is TimerRootSymsSource.Url -> {
                        onLog("parse OTA: ${input.url}")
                        val extracted = extractPackagePartitions(
                            url = input.url,
                            onLog = onLog,
                            reader = null,
                        )
                        bootPath = extracted.bootFile.also { tempBoot = it }.absolutePath
                        xblPath = extracted.xblConfigFile?.also { tempXbl = it }?.absolutePath
                        uefiPath = extracted.uefiFile?.let {
                            tempUefi = it
                            stageUefiFile(it, onLog) ?: it.absolutePath
                        }
                        extracted.vendorBootFile?.let { vendorBoot ->
                            tempVendorBoot = vendorBoot
                            if (stageVendorBootFile(vendorBoot, onLog)) {
                                vendorBoot.delete()
                                tempVendorBoot = null
                            }
                        }
                    }

                    is TimerRootSymsSource.Package -> {
                        /* Read the package where it lies: a seekable descriptor
                         * over the picked document feeds the same Kotlin
                         * extractor the URL path uses, without copying an
                         * 8 GiB package into filesDir first. */
                        val reader = LocalFileRangeReader(appContext.contentResolver, input.uri.toUri())
                        localReader = reader
                        val size = reader.fileLength("local")
                        onLog("local package: ${OtaPayloadExtractor.formatSize(size ?: 0L)}")
                        val extracted = extractPackagePartitions(
                            url = "local",
                            onLog = onLog,
                            reader = reader,
                        )
                        bootPath = extracted.bootFile.also { tempBoot = it }.absolutePath
                        xblPath = extracted.xblConfigFile?.also { tempXbl = it }?.absolutePath
                        uefiPath = extracted.uefiFile?.let {
                            tempUefi = it
                            stageUefiFile(it, onLog) ?: it.absolutePath
                        }
                        extracted.vendorBootFile?.let { vendorBoot ->
                            tempVendorBoot = vendorBoot
                            if (stageVendorBootFile(vendorBoot, onLog)) {
                                vendorBoot.delete()
                                tempVendorBoot = null
                            }
                        }
                    }
                }

                onLog("<k> extract: $bootPath")
                val code = runProcess(
                    ProcessBuilder(
                        buildList {
                            add(binary.absolutePath)
                            add(bootPath)
                            xblPath?.let { add("--xbl-config"); add(it) }
                            uefiPath?.let { add("--uefi"); add(it) }
                            vendorBootPath?.let { add("--vendor-boot"); add(it) }
                            addAll(
                                listOf(
                                    "--format", "ic-syms", "--out", out.absolutePath,
                                    "--work-dir", filesDir.absolutePath,
                                ),
                            )
                        },
                    ).directory(filesDir).redirectErrorStream(true).apply {
                        environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                        environment()["TMPDIR"] = filesDir.absolutePath
                        environment()["HOME"] = filesDir.absolutePath
                    },
                    onLog = onLog,
                    timeoutSeconds = 1800,
                )
                onLog("<k> extract exit code=$code")
                if (code != 0 || !out.isFile) return@withContext ParseResult.Failed(code)
                val release = out.readLines()
                    .firstOrNull { it.startsWith("# build=") }
                    ?.removePrefix("# build=")
                    ?: return@withContext ParseResult.Failed(code, "table carries no build header")
                /* Keep every successfully parsed table in the archive: the
                 * 98260 加载配置 page lists them for explicit loading, like
                 * the GhostLock saved-profile list. */
                archiveTimerRootTable(out)
                ParseResult.Parsed(listOf(release), emptySet(), TIMER_ROOT_SYMS)
            } finally {
                tempBoot?.delete()
                tempXbl?.delete()
                tempUefi?.delete()
                tempVendorBoot?.delete()
                localReader?.close()
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            ParseResult.Failed(1, error.message)
        }
    }

    /** Shared package decode for the URL and local-document sources. */
    private suspend fun extractPackagePartitions(
        url: String,
        onLog: (String) -> Unit,
        reader: HttpRangeReader?,
    ): OtaPayloadExtractor.ExtractedPartitions = OtaPayloadExtractor.extractPartitions(
        url = url,
        workDir = filesDir,
        onLog = onLog,
        wantVendorBoot = isVivoOrIqoo(),
        reader = reader ?: HttpRangeReader(),
    )

    override suspend fun importTimerRootSyms(uri: String): String? = withContext(Dispatchers.IO) {
        /* An ic-syms table is a small text file (tens of KiB). Reading it with
 * readText() used to OOM the ART heap when a boot image (hundreds of MiB)
 * was picked here by mistake - "Failed to allocate a 268501000 byte
 * allocation" - so gate on the reported size first and refuse anything
 * that cannot be a table, pointing at the extractor for real images. */
        val declared = appContext.contentResolver
            .query(uri.toUri(), arrayOf(OpenableColumns.SIZE), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0) else null
            }
        if (declared != null && declared > MAX_SYMS_IMPORT_BYTES) {
            throw IOException(
                "picked file is ${declared} bytes; an ic-syms table is a small text file. " +
                    "To use a boot/vendor_boot image, run 提取符号表 (parse) instead of import",
            )
        }
        /* Stream line-by-line: validate while copying, never hold the whole
 * document, and cap the accepted size defensively for providers that
 * report no SIZE column. */
        val target = File(filesDir, TIMER_ROOT_SYMS)
        val staged = File(filesDir, "$TIMER_ROOT_SYMS.partial")
        var foundTarget = false
        var total = 0L
        try {
            appContext.contentResolver.openInputStream(uri.toUri())
                ?.bufferedReader(Charsets.UTF_8)?.use { reader ->
                    staged.outputStream().bufferedWriter(Charsets.UTF_8).use { writer ->
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.startsWith("__tracepoint_sys_exit=")) foundTarget = true
                            total += line.length + 1
                            if (total > MAX_SYMS_IMPORT_BYTES) {
                                throw IOException(
                                    "file exceeds ${MAX_SYMS_IMPORT_BYTES} bytes while reading; " +
                                        "not an ic-syms table (use 提取符号表 for boot images)",
                                )
                            }
                            writer.write(line)
                            writer.write("\n")
                        }
                    }
                } ?: throw IOException("cannot open $uri")
            if (!foundTarget) {
                throw IOException("not an ic-syms table (no __tracepoint_sys_exit entry)")
            }
            if (!staged.renameTo(target)) {
                target.delete()
                staged.copyTo(target, overwrite = true)
            }
            /* Imports join the parse archive under the same rules, so an
             * imported table is loadable again after another one is staged. */
            archiveTimerRootTable(target)
        } finally {
            staged.delete()
        }
        TIMER_ROOT_SYMS
    }

    override suspend fun stageTimerRootTable(release: String): Boolean = withContext(Dispatchers.IO) {
        val match = listTimerRootTables().firstOrNull { it.release == release }
            ?: return@withContext false
        val source = File(timerRootTablesDir, match.fileName)
        if (!source.isFile) return@withContext false
        runCatching {
            val target = File(filesDir, TIMER_ROOT_SYMS)
            val staged = File(filesDir, "$TIMER_ROOT_SYMS.partial")
            source.copyTo(staged, overwrite = true)
            if (!staged.renameTo(target)) {
                target.delete()
                staged.copyTo(target, overwrite = true)
            }
            staged.delete()
            true
        }.getOrDefault(false)
    }

    override suspend fun autoMatchTimerRootTable(release: String?): String? = withContext(Dispatchers.IO) {
        if (release.isNullOrBlank()) return@withContext null
        val match = listTimerRootTables().firstOrNull { it.release == release }
            ?: return@withContext null
        if (stageTimerRootTable(match.release)) match.release else null
    }

    /** Archived tables, newest parse first, same kernel never twice. */
    private fun listTimerRootTables(): List<TimerRootArchivedTable> = runCatching {
        timerRootTablesDir.listFiles { file ->
            file.isFile && file.name.endsWith(".syms") && !file.name.endsWith(".partial")
        }?.mapNotNull { file ->
            val summary = runCatching { TimerRootTable.summarize(file.readText()) }.getOrNull()
            val release = summary?.release?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            TimerRootArchivedTable(
                release = release,
                symbols = summary.symbols,
                geometryKeys = summary.geometryKeys,
                geometryEssential = summary.geometryEssential,
                fileName = file.name,
            )
        }?.sortedByDescending { it.fileName }
            ?.distinctBy { it.release }
            ?: emptyList()
    }.getOrDefault(emptyList())

    /**
     * Copies [source] into the table archive under its `# build=` kernel
     * (atomically: write .partial, rename). Best effort by design — the
     * parse result never depends on the archive succeeding.
     */
    private fun archiveTimerRootTable(source: File) {
        runCatching {
            val release = TimerRootTable.summarize(source.readText()).release
                ?.takeIf { it.isNotEmpty() } ?: return@runCatching
            val safe = release.replace(Regex("[^A-Za-z0-9._-]"), "_")
            timerRootTablesDir.mkdirs()
            val staged = File(timerRootTablesDir, "$safe.syms.partial")
            val target = File(timerRootTablesDir, "$safe.syms")
            staged.writeText(source.readText())
            if (!staged.renameTo(target)) {
                target.delete()
                staged.copyTo(target, overwrite = true)
                staged.delete()
            }
        }
    }

    override fun timerRootAllowAnyKernel(): Boolean =
        preferences.getBoolean(PrefTimerRootAllowAnyKernel, false)

    override fun setTimerRootAllowAnyKernel(enabled: Boolean) {
        preferences.edit { putBoolean(PrefTimerRootAllowAnyKernel, enabled) }
    }

    override fun launchManagerOnSuccess(): Boolean =
        preferences.getBoolean(PrefLaunchManagerOnSuccess, true)

    override fun setLaunchManagerOnSuccess(enabled: Boolean) {
        preferences.edit { putBoolean(PrefLaunchManagerOnSuccess, enabled) }
    }

    override fun launchRootManager(): String? {
        val pm = appContext.packageManager
        val chosen = ManagerScanner.resolvePackages(preferences.getString(ManagerScanner.PREF_KEY, null))
            .firstOrNull { pkg ->
                runCatching { pm.getLaunchIntentForPackage(pkg) != null }.getOrDefault(false)
            }
            ?: ManagerScanner.scan(pm, appContext.packageName)
                .firstOrNull { candidate ->
                    runCatching { pm.getLaunchIntentForPackage(candidate.packageName) != null }.getOrDefault(false)
                }?.packageName
            ?: return null
        val intent = pm.getLaunchIntentForPackage(chosen) ?: return null
        return runCatching {
            intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            appContext.startActivity(intent)
            chosen
        }.getOrNull()
    }

    override suspend fun runExploitAsTimerRoot(onLog: (String) -> Unit): Int {
        val state = timerRootState()
        if (!state.binaryAvailable) {
            onLog("<t> error: t98260 binary is missing (bundled libtimerroot.so absent and no import)")
            return 1
        }
        val syms = File(filesDir, TIMER_ROOT_SYMS).takeIf { it.isFile }?.readText()
        val managerApk = managerApkPath()
        if (managerApk == null) {
            onLog("<t> warning: no manager APK found; the chain runs without ksud handoff")
        }
        resetRunState()
        return shizukuRunner.runTimerRoot(
            managerApk = managerApk,
            ksudEntry = ksudLibraryChoice(),
            managerPackage = selectedManagerPackage(),
            symsTable = syms,
            safeMode = safeModeEnabled,
            allowAnyKernel = timerRootAllowAnyKernel(),
            onLog = onLog,
        )
    }

    override suspend fun installedManagers(): List<ManagerScanner.Candidate> =
        withContext(Dispatchers.IO) {
            runCatching {
                ManagerScanner.scan(appContext.packageManager, appContext.packageName)
            }.getOrDefault(emptyList())
        }

    override fun profileController(): ProfileConfigController = profileController

    /* debug-ui: preferences for the hidden debug screen. */
    override suspend fun debugSettings(): DebugSettings = DebugSettings(
        exportEnabled = preferences.getBoolean(PrefDebugExportEnabled, true),
        exportLocation = normalizeDebugLocation(preferences.getString(PrefDebugExportLocation, null)),
        kernelLogEnabled = preferences.getBoolean(PrefDebugKernelLogEnabled, true),
    )

    override fun setDebugExportEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugExportEnabled, enabled) }
    }

    override fun setDebugExportLocation(location: String) {
        preferences.edit { putString(PrefDebugExportLocation, normalizeDebugLocation(location)) }
    }

    override fun setDebugKernelLogEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugKernelLogEnabled, enabled) }
    }

    private fun normalizeDebugLocation(value: String?): String {
        val cleaned = value.orEmpty().trim().trim('/').replace(Regex("/{2,}"), "/")
        val safe = cleaned.takeIf { candidate ->
            candidate.isNotEmpty() && candidate.split('/').none { it == ".." || it == "." }
        }
        return safe ?: DefaultDebugLocation
    }

    /* Profile configuration now lives in AndroidProfileConfigController: the
     * repository only wires it and forwards the native document. */

    override suspend fun importOffsets(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = false)

    override suspend fun confirmImport(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = true)

    private fun mergeImported(documents: Map<String, String>, overwrite: Boolean): OffsetImportResult {
        return try {
            val imported = parseImportDocuments(documents)
                ?: return OffsetImportResult.Failed("not a valid profile document")
            /* Unlike export candidates, imports are never compared against the
             * bundled tables: whatever the user picked lands in the store. */
            val fresh = imported.filter { (it["release"] as? String).orEmpty().isNotEmpty() }
            if (fresh.isEmpty()) return OffsetImportResult.AlreadyPresent

            val releases = freshReleases(fresh)
            val overlaps = releases.filter { userProfileStore.containsRelease(it) }
            if (!overwrite && overlaps.isNotEmpty()) {
                return OffsetImportResult.RequiresOverwrite(overlaps)
            }
            if (overwrite) dropReplacedDocuments(releases)
            for ((name, text) in documents) userProfileStore.save(name, text)
            OffsetImportResult.Imported(releases)
        } catch (error: CancellationException) {
            throw error
        } catch (error: UserProfileStore.MissingIncludes) {
            OffsetImportResult.MissingIncludes(error.files)
        } catch (error: Exception) {
            OffsetImportResult.Failed(error.message ?: "import failed")
        }
    }

    /** Confirmed overwrite: drop old documents fully superseded by [releases]. */
    private fun dropReplacedDocuments(releases: List<String>) {
        val incoming = releases.toSet()
        userProfileStore.list().forEach { stored ->
            if (stored.releases.isNotEmpty() && stored.releases.all { it in incoming }) {
                userProfileStore.delete(stored.name)
            }
        }
    }

    /**
     * Parses every picked document, resolving includes against the picked
     * files first (by full name or base name), then the bundled assets.
     * Anything unresolvable is reported so the user can pick it too; only
     * objects carrying a `release` become entries.
     */
    private fun parseImportDocuments(documents: Map<String, String>): List<ValueMap>? {
        val entries = mutableListOf<ValueMap>()
        documents.forEach { (_, text) ->
            entries += userProfileStore.parseEntries(text, extraDocuments = documents)
        }
        return entries.takeIf { it.isNotEmpty() }
    }

    override suspend fun parseSource(
        input: String,
        xblPath: String?,
        uefiPath: String?,
        vendorBootPath: String?,
        overwrite: Boolean,
        onLog: (String) -> Unit,
    ): ParseResult {
        val parsedFile = File(filesDir, "offsets_parse.tmp")
        var tempBootFile: File? = null
        var tempXblFile: File? = null
        var tempUefiFile: File? = null
        var tempVendorBootFile: File? = null
        return try {
            if (overwrite) {
                val pending = pendingParsedDocument
                if (pending != null) {
                    pendingParsedDocument = null
                    dropReplacedDocuments(pending.releases)
                    userProfileStore.save(pending.name, pending.text)
                    return ParseResult.Parsed(pending.releases, pending.missing, pending.name)
                }
            }
            val binary = File(appContext.applicationInfo.nativeLibraryDir, ExtractBinaryName)
            if (!binary.isFile) return ParseResult.Failed(1, "missing native binary: ${binary.absolutePath}")

            /* Remote OTA URLs are resolved by the pure-Kotlin extractor so the
             * Android binary ships without the http stack; local files keep
             * going straight to the Rust extractor. */
            val isRemoteUrl = input.startsWith("http://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true)
            var effectiveUefiPath = uefiPath
            val (effectiveInput, effectiveXblPath) = if (isRemoteUrl) {
                /* Pull only what this parse consumes: boot, plus vendor_boot on
                 * a vivo/iQOO device (the runtime probe reads vr.ko out of it),
                 * plus one physical-load source. */
                val extracted = OtaPayloadExtractor.extractPartitions(
                    url = input,
                    workDir = filesDir,
                    onLog = onLog,
                    wantVendorBoot = isVivoOrIqoo(),
                )
                tempBootFile = extracted.bootFile
                tempXblFile = extracted.xblConfigFile
                tempUefiFile = extracted.uefiFile
                tempVendorBootFile = extracted.vendorBootFile
                extracted.vendorBootFile?.let { vendorBoot ->
                    if (stageVendorBootFile(vendorBoot, onLog)) {
                        vendorBoot.delete()
                        tempVendorBootFile = null
                    }
                }
                /* The uefi image doubles as the runtime's physical-base witness,
                 * so it is the one non-boot image kept on disk; xbl_config is
                 * consumed by the extractor and removed in the cleanup below. */
                if (extracted.uefiFile != null) {
                    effectiveUefiPath = stageUefiFile(extracted.uefiFile, onLog)
                        ?: extracted.uefiFile.absolutePath
                }
                Pair(extracted.bootFile.absolutePath, extracted.xblConfigFile?.absolutePath ?: xblPath)
            } else {
                Pair(input, xblPath)
            }

            /* Before the offset work: a local payload/OTA zip carries
             * vendor_boot, and the vivo/iQOO runtime probe needs it. Kept out
             * of the offsets call so a dump failure can never be mistaken for
             * a parse failure. */
            if (!isRemoteUrl && isVivoOrIqoo()) {
                dumpVendorBootFromPackage(binary, input, onLog)
            }

            parsedFile.delete()
            val args = buildList {
                add(effectiveInput)
                if (effectiveXblPath != null) {
                    add("--xbl-config")
                    add(effectiveXblPath)
                }
                if (effectiveUefiPath != null) {
                    add("--uefi")
                    add(effectiveUefiPath)
                }
                if (vendorBootPath != null) {
                    add("--vendor-boot")
                    add(vendorBootPath)
                }
                /* --format conf: the extractor output is already the flattened
                 * profile (no includes, credential template inlined), so the
                 * stored document needs no legacy conversion. */
                addAll(listOf("--format", "conf", "--out", parsedFile.absolutePath, "--work-dir", filesDir.absolutePath))
            }
            onLog("<k> extract: $effectiveInput")
            val code = runProcess(
                ProcessBuilder(listOf(binary.absolutePath) + args).directory(filesDir).redirectErrorStream(true).apply {
                        environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                        environment()["TMPDIR"] = filesDir.absolutePath
                        environment()["HOME"] = filesDir.absolutePath
                    },
                onLog = onLog,
                timeoutSeconds = 1800,
            )
            onLog("<k> extract exit code=$code")
            if (code != 0 || !parsedFile.isFile) return ParseResult.Failed(code)
            val document = parsedFile.readText()
            val fresh = parseEntries(document) ?: return ParseResult.Failed(code, "invalid extractor output")
            /* Parsed reports are normalized (see canonicalizeParsedEntries)
             * but otherwise stored even when they match a bundled profile;
             * loading decides whether they take effect. */
            val filtered = fresh.mapNotNull { it.asValueMap() }
                .filter { (it["release"] as? String).orEmpty().isNotEmpty() }
            if (filtered.isEmpty()) return ParseResult.AlreadyPresent
            /* Normalize against the bundled twin before anything is stored or
             * compared: the extractor's report carries null placeholders and
             * fallback guesses for the sections it cannot measure, and a
             * stored half-truth (copy_size = 136, collisions = 4, a
             * tcp_zerocopy route group) would override the verified builtin
             * at merge time. */
            val canonical = canonicalizeParsedEntries(filtered)
            val documentText = canonical.joinToString("\n\n") { HoconSupport.render(it) }
            val releases = freshReleases(filtered)
            val missing = missingSidecarFields(filtered)
            val overlaps = releases.filter { userProfileStore.containsRelease(it) }
            val name = parsedDocumentName(releases)
            if (!overwrite && overlaps.isNotEmpty()) {
                pendingParsedDocument = PendingParsedDocument(name, documentText, releases, missing)
                return ParseResult.RequiresOverwrite(overlaps, missing)
            }
            dropReplacedDocuments(releases)
            userProfileStore.save(name, documentText)
            ParseResult.Parsed(releases, missing, name)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            ParseResult.Failed(1, error.message)
        } finally {
            parsedFile.delete()
            tempBootFile?.delete()
            tempXblFile?.delete()
            tempUefiFile?.delete()
            tempVendorBootFile?.delete()
            sweepStaleExtractionTemps()
        }
    }

    /**
     * Removes staging the parse no longer needs: timestamped partition files
     * from earlier runs (including ones interrupted before their own cleanup)
     * and the extractor's payload/dump work directories. The images the
     * runtime reads — `vendor_boot.img` and `uefi.img` — are deliberately kept.
     */
    private fun sweepStaleExtractionTemps() {
        val keep = setOf(VendorBootFileName, UefiFileName)
        runCatching {
            filesDir.listFiles()?.forEach { entry ->
                val name = entry.name
                when {
                    name.startsWith("ghostlock_ota_") -> entry.delete()
                    name.startsWith("ghostlock-payload-") ||
                        name.startsWith("ghostlock-dump-") -> entry.deleteRecursively()
                    name == "offsets_parse.tmp" -> entry.delete()
                    /* Interrupted staging copies of the runtime images. */
                    name.endsWith(".staging") || name.endsWith(".dump") -> entry.delete()
                    name in keep -> Unit
                }
            }
        }
    }

    /**
     * Stages [source] as `filesDir/vendor_boot.img` after re-checking the
     * vendor_boot magic — the file name the native runtime looks for. Returns
     * false (and stages nothing) for any other image, so a boot.img picked by
     * mistake never masquerades as vendor_boot.
     */
    private fun stageVendorBootFile(source: File, onLog: (String) -> Unit): Boolean {
        val looksRight = runCatching {
            source.inputStream().use { input ->
                val header = readExactHeader(input, VendorBootMagic.length) ?: return@runCatching false
                String(header, Charsets.US_ASCII) == VendorBootMagic
            }
        }.getOrDefault(false)
        if (!looksRight) {
            onLog("vendor_boot: rejected ${source.name} (magic mismatch)")
            return false
        }
        return runCatching {
            copyIntoPlace(source, File(filesDir, VendorBootFileName))
            onLog("vendor_boot: staged -> $VendorBootFileName (runtime vr.ko probe)")
            true
        }.getOrDefault(false)
    }

    /**
     * Copies [source] onto [target] without ever passing through a missing
     * target: the data lands on a temp file that is renamed into place.
     *
     * `File.copyTo(target, overwrite = true)` deletes the target first, which
     * matters whenever source and target are the same file — the app's own
     * cache already names the picked image `vendor_boot.img`, so the staging
     * copy used to delete the image it was asked to stage (the extractor then
     * reported "cannot read .../vendor_boot.img: No such file"). A same-file
     * copy is a no-op here.
     */
    private fun copyIntoPlace(source: File, target: File) {
        if (source.canonicalFile == target.canonicalFile) return
        val temp = File(target.parentFile, target.name + ".staging")
        temp.delete()
        source.copyTo(temp, overwrite = true)
        if (!temp.renameTo(target)) {
            temp.copyTo(target, overwrite = true)
            temp.delete()
        }
    }

    /**
     * Stages [source] as `filesDir/uefi.img`, the path the native runtime reads
     * when it cross-checks the profile's physical load base. A PE image starts
     * with `MZ`; anything else is left un-staged (and the caller falls back to
     * the temporary path for this parse).
     */
    private fun stageUefiFile(source: File, onLog: (String) -> Unit): String? {
        val looksRight = runCatching {
            source.inputStream().use { input ->
                val header = readExactHeader(input, 2) ?: return@runCatching false
                header[0] == 'M'.code.toByte() && header[1] == 'Z'.code.toByte()
            }
        }.getOrDefault(false)
        if (!looksRight) {
            onLog("uefi: not a PE image, keeping it only for this parse")
            return null
        }
        return runCatching {
            val target = File(filesDir, UefiFileName)
            copyIntoPlace(source, target)
            onLog("uefi: staged -> $UefiFileName")
            target.absolutePath
        }.getOrNull()
    }

    /**
     * Pulls `vendor_boot` out of a local payload.bin / OTA zip through the
     * extractor's `--dump-partition` and stages it for the runtime.
     *
     * Best effort by design: only vivo/iQOO devices use the module, packages
     * without the partition are normal, and every failure path is logged and
     * ignored so the offsets parse is never affected.
     */
    private suspend fun dumpVendorBootFromPackage(
        binary: File,
        input: String,
        onLog: (String) -> Unit,
    ) {
        val head = runCatching {
            val file = File(input)
            if (!file.isFile) return@runCatching null
            file.inputStream().use { stream -> readExactHeader(stream, 4) }
        }.getOrNull() ?: return
        /* Same gate as the extractor's own payload detection: CrAU or a zip. */
        val isPayload = head.contentEquals(byteArrayOf(0x43, 0x72, 0x41, 0x55)) ||
            head.contentEquals(byteArrayOf(0x50, 0x4B, 0x03, 0x04))
        if (!isPayload) return

        /* Dump next to the staged name, never onto it: a package without the
         * partition, or a dump that fails half-way, must leave an image the
         * user staged earlier (or that a previous package provided) intact.
         * The old path wrote straight to vendor_boot.img and deleted it on
         * failure. */
        val dumped = File(filesDir, "$VendorBootFileName.dump")
        dumped.delete()
        onLog("<k> vendor_boot: extracting from the package")
        val code = runCatching {
            runProcess(
                ProcessBuilder(
                    listOf(
                        binary.absolutePath, input,
                        "--dump-partition", "vendor_boot",
                        "--dump-out", dumped.absolutePath,
                        "--dump-only",
                        "--work-dir", filesDir.absolutePath,
                    ),
                ).directory(filesDir).redirectErrorStream(true).apply {
                    environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                    environment()["TMPDIR"] = filesDir.absolutePath
                    environment()["HOME"] = filesDir.absolutePath
                },
                onLog = onLog,
                timeoutSeconds = 600,
            )
        }.getOrNull()
        if (code != 0) {
            /* Normal for packages without the partition; the native probe
             * simply stays on its built-in defaults (or on the image already
             * staged). */
            onLog("vendor_boot: not available from this package (exit=$code)")
            dumped.delete()
            return
        }
        if (stageVendorBootFile(dumped, onLog)) {
            onLog("vendor_boot: package image replaced the staged one")
        } else {
            onLog("vendor_boot: package dump rejected; keeping the previously staged image")
        }
        dumped.delete()
    }

    private fun isVivoOrIqoo(): Boolean {
        val identity = listOf(Build.MANUFACTURER, Build.BRAND).joinToString(" ")
            .lowercase(Locale.ROOT)
        return identity.contains("vivo") || identity.contains("iqoo")
    }

    override fun stagedImagePath(fileName: String): String? {
        val target = File(filesDir, fileName)
        return target.absolutePath.takeIf { target.isFile && target.length() > 0L }
    }

    override fun stageVendorBootImage(sourcePath: String) {
        runCatching {
            copyIntoPlace(File(sourcePath), File(filesDir, VendorBootFileName))
        }
    }

    override suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int =
        withDebugAttackLog("direct", onLog) { archivedLog, debugDir, writeSidecar ->
            runExploitBinary(pair, "libghostlock.so", archivedLog, debugDir, writeSidecar)
        }

    override suspend fun runExploitWithShizuku(pair: CpuPair, onLog: (String) -> Unit): Int {
        return withDebugAttackLog("shizuku", onLog) { archivedLog, debugDir, writeSidecar ->
            archivedLog("<s> resolving profile")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            val profileBlob = profileController.nativeDocument(config)
            archivedLog(
                "<s> profile resolved hasProfile=${config.hasProfile} " +
                    "blob=${profileBlob?.size ?: 0} invalid=${config.invalidPaths.size}",
            )
            when {
                !config.hasProfile || profileBlob == null -> {
                    archivedLog("<s> error: profile is unavailable for $release")
                    1
                }

                config.invalidPaths.isNotEmpty() -> {
                    archivedLog(
                        "<s> error: profile has ${config.invalidPaths.size} invalid field(s): " +
                            config.invalidPaths.take(6).joinToString(),
                    )
                    1
                }

                else -> {
                    /* Mirror the UserService patch so the dumped blob is the
                     * effective one native will actually receive. */
                    val runtimeBlob = if (safeModeEnabled) {
                        NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                    } else {
                        profileBlob
                    }
                    dumpRuntimeProfile(archivedLog, writeSidecar, release, pair, runtimeBlob)
                    archivedLog("<b> starting UserService")
                    resetRunState()
                    shizukuRunner.run(
                        pair, safeModeEnabled, forceAttackTest, profileBlob, debugDir,
                        selectedManagerPackage(), archivedLog,
                    ) { step, status ->
                        if (status == "disabled") clearRunState() else applyRunStatus(step, status)
                    }
                }
            }
        }
    }

    /* --- attack step status ------------------------------------------------
     * The native process reports each step over stdout and waits for an ACK on
     * stdin. The app persists the status here; a kernel panic leaves the last
     * in_progress step on disk for the next launch to read. */

    private val runStateLock = Any()
    private var runSteps: LinkedHashMap<String, String> = LinkedHashMap()

    private fun persistRunStateLocked() {
        val json = RunStateCodec.encode(runSteps, System.currentTimeMillis())
        runCatching {
            FileOutputStream(File(filesDir, RunStateFileName)).use { out ->
                out.write(json.toByteArray(StandardCharsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
        }
    }

    private fun resetRunState() = synchronized(runStateLock) {
        runSteps = LinkedHashMap<String, String>().apply {
            RunStateCodec.Steps.forEach { put(it, RunStateCodec.NotStarted) }
        }
        persistRunStateLocked()
    }

    private fun applyRunStatus(step: String, status: String) = synchronized(runStateLock) {
        if (!runSteps.containsKey(step)) return@synchronized
        runSteps[step] = status
        persistRunStateLocked()
    }

    private fun clearRunState() = runCatching { File(filesDir, RunStateFileName).delete() }

    /** Handles one stdout line; true when it was a status event, not a log line. */
    private fun handleStatusLine(line: String, process: AtomicReference<Process?>): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            clearRunState()
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size < 2) return true
        applyRunStatus(parts[0], parts[1])
        runCatching {
            process.get()?.outputStream?.apply {
                write(StatusAck.toByteArray(StandardCharsets.UTF_8))
                flush()
            }
        }
        return true
    }

    override suspend fun lastRunStuckStep(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(filesDir, RunStateFileName)
            if (!file.isFile) return@runCatching null
            RunStateCodec.parseStuckStep(file.readText())
        }.getOrNull()
    }

    private suspend fun withDebugAttackLog(
        entry: String,
        onLog: (String) -> Unit,
        run: suspend ((String) -> Unit, String?, (String, ByteArray) -> Boolean) -> Int,
    ): Int {
        val settings = debugSettings()
        if (!settings.exportEnabled) return run(onLog, null) { _, _ -> false }
        val archive = DebugAttackLog.open(appContext, entry, settings.exportLocation)
        if (archive == null) {
            onLog("<k> warning: cannot create ${settings.exportLocation} debug log")
            return run(onLog, null) { _, _ -> false }
        }
        val archivedLog: (String) -> Unit = { line ->
            runCatching { archive.append(line) }
            onLog(line)
        }
        val writeSidecar: (String, ByteArray) -> Boolean = { name, bytes ->
            runCatching { archive.writeSidecar(name, bytes) }.getOrDefault(false)
        }
        return try {
            /* First line of every archived run log: which app build produced it. */
            archivedLog(
                "<k> GhostLock ${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE} " +
                    "build ${BuildInfo.BUILD_TIME_LABEL}",
            )
            archivedLog("<k> debug log: ${archive.folderPath}/${archive.displayName}")
            archivedLog("<k> debug dump dir: ${archive.folderFile.absolutePath}")
            run(
                archivedLog,
                if (settings.kernelLogEnabled) archive.folderFile.absolutePath else null,
                writeSidecar,
            )
        } finally {
            runCatching { archive.close() }
        }
    }

    /**
     * Writes the effective runtime profile into the attempt folder: the resolved
     * HOCON (`profile.conf`) and the exact GLK1 v2 bytes handed to native
     * (`profile.bin`). No-op when debug export is disabled.
     */
    private fun dumpRuntimeProfile(
        log: (String) -> Unit,
        writeSidecar: (String, ByteArray) -> Boolean,
        release: String,
        pair: CpuPair,
        blob: ByteArray?,
    ) {
        val conf = runCatching { profileController.renderResolvedForDebug(release, pair) }.getOrNull()
        val confWritten = conf?.let {
            writeSidecar("profile.conf", it.toByteArray(StandardCharsets.UTF_8))
        } ?: false
        val blobWritten = blob?.let { writeSidecar("profile.bin", it) } ?: false
        if (confWritten || blobWritten) {
            log("<k> runtime profile written: profile.conf/profile.bin")
        }
    }

    override fun requestShizukuPermission() = shizukuRunner.requestPermission()

    override fun setShizukuStatusListener(listener: (() -> Unit)?) =
        shizukuRunner.setStatusListener(listener)

    private suspend fun runExploitBinary(
        pair: CpuPair,
        binaryName: String,
        onLog: (String) -> Unit,
        debugDir: String?,
        writeSidecar: (String, ByteArray) -> Boolean,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, binaryName)
            require(binary.isFile) { "missing native binary: ${binary.absolutePath}" }
            val ksud = resolveKsudPath(onLog)
            val isApatch = ManagerScanner.isApatch(ksud)
            val daemonTag = if (isApatch) "[apd]" else "[ksu]"
            if (ksud != null) {
                onLog("<k> ${if (isApatch) "apd" else "ksud"} ready: ${ksud.absolutePath}")
            } else {
                onLog("<k> warning: ksud/apd not found")
            }
            // U01-S14: a per-run KernelSU log path so a previous run's markers
            // can never satisfy the handoff probe; passed to the native process.
            val ksuLog = File(workDir, ksuLogName(System.currentTimeMillis()))
            val nativeLog = File(workDir, NativeLogFileName)
            nativeLog.writeText("")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            onLog(
                "<k> profile: hasProfile=${config.hasProfile} " +
                    "invalid=${config.invalidPaths.size} release=$release",
            )
            if (!config.hasProfile) {
                error(
                    "no profile matched $release; import its .conf and select it, " +
                        "or pick a built-in release",
                )
            }
            if (config.invalidPaths.isNotEmpty()) {
                error(
                    "profile has ${config.invalidPaths.size} invalid field(s): " +
                        config.invalidPaths.take(6).joinToString(),
                )
            }
            var profileBlob = profileController.nativeDocument(config)
                ?: error("profile is unavailable for $release")
            // v2: safe_mode lives in the meta section; there is no fixed slot
            // offset, so the blob is rescanned and rewritten.
            if (safeModeEnabled) {
                profileBlob = NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
            }
            dumpRuntimeProfile(onLog, writeSidecar, release, pair, profileBlob)
            val ksuOffset = AtomicLong()
            val nativeOffset = AtomicLong()
            val processRef = AtomicReference<Process?>(null)
            // tag root-script lines so they cannot be read as the native stages'
            val ksuSink: (String) -> Unit = { onLog("$daemonTag $it") }
            // status events are consumed here (persisted + ACKed); plain lines are logs
            val nativeSink: (String) -> Unit = { line ->
                if (!handleStatusLine(line, processRef)) onLog(line)
            }
            val tailer = Thread {
                try {
                    while (!Thread.currentThread().isInterrupted) {
                        tailKsuLog(nativeLog, nativeOffset, nativeSink)
                        tailKsuLog(ksuLog, ksuOffset, ksuSink)
                        Thread.sleep(200)
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }.apply {
                name = "ksu-log-tailer"
                isDaemon = true
                start()
            }
            val argv = mutableListOf(
                binary.absolutePath,
                "--ghostlock-app-call",
                "--enable-status-record",
            )
            if (forceAttackTest) {
                argv += "--force-attack"
            }
            if (!debugDir.isNullOrEmpty()) {
                argv += listOf("--dump-kernel-log", debugDir)
            }
            val command = ProcessBuilder(argv)
                .directory(workDir)
                .redirectErrorStream(true)
                .redirectOutput(nativeLog)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                    environment()["TMPDIR"] = workDir.absolutePath
                    environment()["HOME"] = workDir.absolutePath
                    environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                    if (ksud != null) environment()["GHOSTLOCK_KSUD"] = ksud.absolutePath
                }
            onLog("<b> starting native: ${binary.absolutePath}")
            resetRunState()
            try {
                val nativeCode = runProcess(
                    command,
                    onLog = {},
                    captureOutput = false,
                    stdin = profileBlob,
                    frameStdin = true,
                    onProcess = { processRef.set(it) },
                )
                onLog("<b> native exited code=$nativeCode")
                nativeCode
            } finally {
                withContext(Dispatchers.IO) {
                    tailer.interrupt()
                    tailer.join(1000)
                    tailKsuLog(nativeLog, nativeOffset, onLog)
                    tailKsuLog(ksuLog, ksuOffset, ksuSink)
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("<-> error: ${error::class.simpleName}: ${error.message}")
            1
        }
    }

    override suspend fun readDocument(uri: String): String =
        appContext.contentResolver.openInputStream(uri.toUri())?.bufferedReader()?.use { it.readText() } ?: throw IOException("cannot open $uri")

    override suspend fun cacheDocument(uri: String, fileName: String): String {
        val target = File(filesDir, fileName)
        appContext.contentResolver.openInputStream(uri.toUri())?.use { input ->
            target.outputStream().use(input::copyTo)
        } ?: throw IOException("cannot open $uri")
        return target.absolutePath
    }

    override suspend fun userProfiles(): List<UserProfileFile> =
        withContext(Dispatchers.IO) {
            userProfileStore.list().map { stored ->
                UserProfileFile(
                    name = stored.name,
                    releases = stored.releases,
                    importedAt = stored.importedAt,
                    sizeBytes = stored.sizeBytes,
                    parseError = stored.parseError,
                    version = stored.version,
                )
            }
        }

    override suspend fun deleteUserProfile(name: String): Boolean {
        val deleted = withContext(Dispatchers.IO) { userProfileStore.delete(name) }
        if (deleted) profileController.onUserProfileDeleted(name)
        return deleted
    }

    override suspend fun renameUserProfile(name: String, newName: String): String? {
        val renamed = withContext(Dispatchers.IO) { userProfileStore.rename(name, newName) }
        if (renamed != null) profileController.onUserProfileRenamed(name, renamed)
        return renamed
    }

    /** Renders a stored document as HOCON and shares it; returns the URI. */
    override suspend fun exportUserProfile(name: String): String {
        val hocon = withContext(Dispatchers.IO) { userProfileStore.exportHocon(name) }
            ?: throw IOException("cannot export $name")
        return publishOffsets(OffsetCandidate(name.substringBeforeLast('.'), hocon))
    }

    /**
     * Converts a stored legacy document into the current layout and stores the
     * result as a new user document; returns its name, or null on failure.
     */
    override suspend fun convertUserProfile(name: String): String? {
        val hocon = withContext(Dispatchers.IO) { userProfileStore.exportHocon(name) }
            ?: return null
        val base = name.substringBeforeLast('.')
        return withContext(Dispatchers.IO) {
            userProfileStore.save("$base-converted.conf", hocon)
        }
    }

    /* ---- editing session: isolated from the live attack controller ---- */

    private var editSession: AndroidProfileConfigController? = null
    private var editSessionTargetName: String? = null
    private var editSessionTargetRelease: String? = null
    private var editSessionLive = false

    override suspend fun beginEditSession(name: String?): ProfileConfig? =
        withContext(Dispatchers.IO) {
            endEditSession()
            val deviceRelease = System.getProperty("os.version", "").orEmpty()
            val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
            /* A stored document is edited against its own release: the device
             * release would resolve the bundled profile instead and hide the
             * imported geometry. Only the live controller stays device-keyed. */
            val targetRelease = name?.let { userProfileStore.releasesOf(it).firstOrNull() }
                ?: deviceRelease
            val sessionPreferences = appContext.getSharedPreferences(
                EditSessionPreferences,
                Context.MODE_PRIVATE,
            )
            sessionPreferences.edit { clear() }
            editSessionLive = name != null && name == profileController.activeUserProfile()
            if (editSessionLive) {
                val overrides = profileController.overridesSnapshot(deviceRelease)
                if (overrides.isNotEmpty()) {
                    /* The store keeps one entry per release, so wrap it back. */
                    sessionPreferences.edit(commit = true) {
                        putString(
                            AndroidProfileConfigController.PrefDebugProfileOverrides,
                            HoconSupport.render(valueMapOf(deviceRelease to overrides)),
                        )
                    }
                }
            }
            val session = AndroidProfileConfigController(
                context = appContext,
                filesDir = filesDir,
                userProfiles = userProfileStore,
                preferences = sessionPreferences,
                forcedUserProfile = name,
                forcedBuiltinRelease = profileController.activeBuiltinRelease(),
            )
            editSession = session
            editSessionTargetName = name
            editSessionTargetRelease = targetRelease
            runCatching { session.load(targetRelease, pair) }.getOrNull()
        }

    override fun editSessionController(): ProfileConfigController? = editSession

    override fun editSessionIsLive(): Boolean = editSessionLive

    override fun editSessionTarget(): String? = editSessionTargetName

    override fun editSessionRelease(): String? = editSessionTargetRelease

    override suspend fun saveEditSessionInPlace(): Boolean = withContext(Dispatchers.IO) {
        if (editSessionLive) return@withContext false
        val session = editSession ?: return@withContext false
        val target = editSessionTargetName ?: return@withContext false
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext false
        val document = session.renderResolved(release, pair) ?: return@withContext false
        userProfileStore.overwrite(target, document)
    }

    override suspend fun commitEditSession(): Boolean = withContext(Dispatchers.IO) {
        if (!editSessionLive) return@withContext false
        val session = editSession ?: return@withContext false
        val release = System.getProperty("os.version", "").orEmpty()
        profileController.replaceOverrides(release, session.overridesSnapshot(release))
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext false
        runCatching { profileController.load(release, pair) }.isSuccess
    }

    override suspend fun saveEditSessionAsNew(): String? = withContext(Dispatchers.IO) {
        val session = editSession ?: return@withContext null
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
        val stem = (editSessionTargetName ?: release)
            .substringBeforeLast('.')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
        val name = "${stem.ifEmpty { "profile" }}-edited.conf"
        if (session.saveResolved(release, pair, name)) name else null
    }

    override suspend fun exportEditSession(): String = withContext(Dispatchers.IO) {
        val session = editSession ?: throw IOException("no editing session")
        val release = editSessionTargetRelease
            ?: System.getProperty("os.version", "").orEmpty()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: throw IOException("no cpu pair")
        val document = session.renderResolved(release, pair)
            ?: throw IOException("cannot render the edited profile")
        val stem = editSessionTargetName?.substringBeforeLast('.') ?: release
        publishOffsets(OffsetCandidate(stem.ifEmpty { release }, document))
    }

    override fun endEditSession() {
        editSession = null
        editSessionTargetName = null
        editSessionTargetRelease = null
        editSessionLive = false
    }

    override suspend fun publishOffsets(candidate: OffsetCandidate): String {
        val safeRelease = candidate.release.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "offsets-$safeRelease.conf")
            put(MediaStore.Downloads.MIME_TYPE, "text/plain")
        }
        val uri = appContext.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: throw IOException("cannot create download entry")
        appContext.contentResolver.openOutputStream(uri)?.use { output ->
            output.write(candidate.document.toByteArray(StandardCharsets.UTF_8))
        } ?: throw IOException("cannot open download entry")
        return uri.toString()
    }

    override suspend fun readTimerRootSyms(): String? = withContext(Dispatchers.IO) {
        val syms = File(filesDir, TIMER_ROOT_SYMS)
        if (!syms.isFile) return@withContext null
        runCatching { syms.readText() }.getOrNull()
    }

    override suspend fun writeTimerRootSyms(text: String): Boolean = withContext(Dispatchers.IO) {
        val syms = File(filesDir, TIMER_ROOT_SYMS)
        if (!syms.isFile) return@withContext false
        /* Atomic-ish: stage the edit, then rename over the live table so a
         * crash mid-write can never leave a half table behind. */
        val staged = File(filesDir, "$TIMER_ROOT_SYMS.edit")
        try {
            staged.writeText(text)
            if (!staged.renameTo(syms)) {
                syms.delete()
                staged.copyTo(syms, overwrite = true)
            }
            true
        } catch (error: IOException) {
            false
        } finally {
            staged.delete()
        }
    }

    override suspend fun publishTimerRootSyms(): String = withContext(Dispatchers.IO) {
        val syms = File(filesDir, TIMER_ROOT_SYMS)
        if (!syms.isFile) throw IOException("no ic-syms table staged")
        val summary = TimerRootTable.summarize(syms.readText())
        if (!summary.hasTracepointTarget) throw IOException("staged table is incomplete")
        val safeRelease = (summary.release ?: "unknown").replace(Regex("[^A-Za-z0-9._-]"), "_")
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "timerroot-syms-$safeRelease.txt")
            put(MediaStore.Downloads.MIME_TYPE, "text/plain")
        }
        val uri = appContext.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IOException("cannot create download entry")
        appContext.contentResolver.openOutputStream(uri)?.use { output ->
            output.write(syms.readBytes())
        } ?: throw IOException("cannot open download entry")
        uri.toString()
    }

    override fun close() {
        shizukuRunner.close()
        synchronized(processes) {
            processes.forEach(Process::destroyForcibly)
            processes.clear()
        }
    }

    /**
     * Legacy/parse helper: reads HOCON or JSON text into a list of entries.
     * Stored user documents are parsed by [UserProfileStore] instead.
     */
    private fun parseEntries(text: String): ValueList? {
        if (text.isBlank()) return null
        return try {
            when (val value = HoconSupport.parseValue(text)) {
                is List<*> -> value.asValueList()
                is Map<*, *> -> ValueList().apply { value.asValueMap()?.let(::add) }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private class PendingParsedDocument(
        val name: String,
        val text: String,
        val releases: List<String>,
        val missing: Set<String>,
    )

    /**
     * Normalizes parsed extractor output before it is stored as a user
     * document. Null leaves (fields the extractor could not measure, like
     * the cred ref images or kernel_phys_offset) are dropped outright, and
     * when the release has a bundled twin the sections the extractor cannot
     * derive (execution / route / fallback / cred / kernelsnitch / vr_guard
     * and the recommendation flags) are taken from the twin wholesale — the
     * stored document then reads like the bundled one, instead of carrying
     * fallback guesses that override the twin at merge time. The measured
     * sections (offset / task_struct) keep the parsed values on top of the
     * twin's base, kernel_phys_load falls back to the twin when the parse
     * did not supply one, and keys only the parsed report carries survive
     * as-is. Entries without a bundled twin are only null-dropped.
     */
    private fun canonicalizeParsedEntries(entries: List<ValueMap>): List<ValueMap> =
        entries.map { entry ->
            val release = (entry["release"] as? String).orEmpty()
            val cleaned = dropNullLeaves(entry.copyValue()).asValueMap() ?: valueMapOf()
            val builtin = builtinProfiles.documentFor(release)
                ?.let { HoconSupport.parseValue(it).asValueMap() }
            if (builtin == null) {
                cleaned
            } else {
                bundledAuthoritativeSections.forEach { section ->
                    builtin[section].asValueMap()?.let { branch ->
                        cleaned[section] = branch.copyValue()
                    } ?: cleaned.remove(section)
                }
                bundledAuthoritativeFlags.forEach { flag ->
                    (builtin[flag] as? Number)?.let { cleaned[flag] = it.toLong() }
                }
                parsedAuthoritativeSections.forEach { section ->
                    val base = builtin[section].asValueMap()
                        ?.let { asMutableMap(it.copyValue().asValueMap() ?: valueMapOf()) }
                        ?: valueMapOf()
                    val measured = cleaned[section].asValueMap()
                    cleaned[section] = deepMergeValues(base, measured)
                }
                if (cleaned["kernel_phys_load"] == null) {
                    (builtin["kernel_phys_load"] as? Number)?.let { cleaned["kernel_phys_load"] = it.toLong() }
                }
                cleaned
            }
        }

    /** Recursively removes null leaves; a null is an unmeasured field, and a
     * stored null both renders as noise and blocks nothing at merge time. */
    private fun dropNullLeaves(value: Any?): Any? = when (value) {
        is Map<*, *> -> ValueMap().apply {
            value.forEach { (key, item) ->
                dropNullLeaves(item)?.let { put(key.toString(), it) }
            }
        }

        is List<*> -> ValueList().apply {
            value.forEach { item -> dropNullLeaves(item)?.let(::add) }
        }

        else -> value
    }

    /**
     * Fields a parsed profile still lacks that only an xbl_config FDT or uefi
     * memory map can fill. Used to prompt for the optional sidecars.
     */
    private fun missingSidecarFields(entries: List<ValueMap>): Set<String> =
        if (entries.isNotEmpty() && entries.all { it.getLongAt("kernel_phys_load") == null }) {
            setOf("kernel_phys_load")
        } else {
            emptySet()
        }

    private fun parsedDocumentName(releases: List<String>): String {
        val stem = releases.firstOrNull().orEmpty()
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .ifEmpty { "parsed" }
        return "$stem.conf"
    }

    private fun freshReleases(entries: List<*>): List<String> =
        entries.mapNotNull { (it.asValueMap()?.get("release") as? String) }.distinct()

    private fun isKernelSupported(): Boolean {
        val version = System.getProperty("os.version", "").orEmpty()
        return version in builtinProfiles.unames || importedOffsetsMatch(version)
    }

    private fun importedOffsetsMatch(version: String): Boolean =
        userProfileStore.containsRelease(version)

    private fun importedOffsetsRecommendShizuku(version: String): Boolean =
        userProfileStore.recommendsShizuku(version)

    private fun buildCpuPairs() {
        cpuPairs.clear()
        cpuPairLabels.clear()
        val online = parseCpuList(readSysFile("/sys/devices/system/cpu/online"))
        online.groupBy { readMaxFreq(it) }.filterKeys { it > 0 }.toSortedMap(compareByDescending { it }).forEach { (freq, cluster) ->
                cluster.sorted().chunked(2).filter { it.size == 2 }.forEach { pair ->
                    cpuPairs += CpuPair(pair[0], pair[1])
                    cpuPairLabels += "${pair[0]},${pair[1]} · ${formatFreq(freq)}"
                }
            }
        if (CpuPair(0, 1) !in cpuPairs) {
            cpuPairs += CpuPair(0, 1)
            val freq = readMaxFreq(0)
            cpuPairLabels += "0,1" + if (freq > 0) " · ${formatFreq(freq)}" else ""
        }
    }

    private fun restoreCpuPair() {
        val saved = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).getString("cpu_pair", null) ?: return
        val pair = saved.split(',').mapNotNull { it.trim().toIntOrNull() }
        if (pair.size == 2) cpuPairs.indexOf(CpuPair(pair[0], pair[1])).takeIf { it >= 0 }?.let { selectedCpuPair = it }
    }

    private fun restoreShizukuPreference() {
        val prefs = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
        shizukuPreferenceSet = prefs.getBoolean("shizuku_explicit", false)
        shizukuEnabled = prefs.getBoolean("shizuku_enabled", false)
    }

    private fun restoreForceAttackTest() {
        forceAttackTest = preferences.getBoolean(PrefForceAttackTest, false)
    }

    private fun parseCpuList(value: String): List<Int> = value.split(',').flatMap { part ->
        val range = part.trim().split('-').mapNotNull { it.toIntOrNull() }
        when (range.size) {
            1 -> range
            2 -> (range[0]..range[1]).toList()
            else -> emptyList()
        }
    }

    private fun readMaxFreq(cpu: Int): Long = readSysFile("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").toLongOrNull() ?: -1L

    private fun formatFreq(khz: Long): String =
        if (khz >= 1_000_000L) "%.2f GHz".format(Locale.ROOT, khz / 1_000_000.0) else "%.0f MHz".format(Locale.ROOT, khz / 1000.0)

    private fun readSysFile(path: String): String = File(path).takeIf { it.isFile }?.useLines { it.firstOrNull()?.trim().orEmpty() } ?: ""

    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    private fun validDeviceName(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

    private fun resolveDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty()
        val marketName = when (manufacturer.lowercase(Locale.ROOT)) {
            "xiaomi" -> firstValidProperty("ro.product.marketname")
            "oppo", "oneplus", "realme", "oplus" -> {
                val cn = Locale.getDefault().country.equals("CN", true)
                firstValidProperty(
                    *(if (cn) arrayOf(
                        "ro.vendor.oplus.market.name", "ro.vendor.oplus.market.enname"
                    ) else arrayOf("ro.vendor.oplus.market.enname", "ro.vendor.oplus.market.name"))
                )
            }

            "vivo" -> firstValidProperty("ro.vivo.market.name")
            "honor", "huawei" -> firstValidProperty("ro.config.marketing_name")
            "zte", "nubia" -> firstValidProperty("ro.vendor.product.ztename")
            else -> null
        }
        return marketName ?: listOfNotNull(
            manufacturer, Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) }, Build.MODEL.orEmpty()
        ).filter { it.isNotBlank() }.joinToString(" ")
    }

    private fun resolveSocName(): String = listOf(
        systemProperty("ro.soc.manufacturer"),
        systemProperty("ro.soc.model"),
    ).mapNotNull(::validDeviceName).joinToString(" ").ifBlank { "unknown" }

    private fun firstValidProperty(vararg keys: String): String? = keys.asSequence().firstNotNullOfOrNull { validDeviceName(systemProperty(it)) }

    /** First manager daemon binary (libksud.so / libapd.so) in resolvePackages order, or null. */
    private fun resolveKsudPath(onLog: (String) -> Unit): File? =
        ManagerScanner.resolveDaemonBinary(appContext.packageManager, selectedManagerPackage())
            ?: run {
                onLog("<k> no manager app with libksud.so / libapd.so found")
                null
            }

    private suspend fun runProcess(
        builder: ProcessBuilder,
        onLog: (String) -> Unit = {},
        timeoutSeconds: Long = 300,
        captureOutput: Boolean = true,
        stdin: ByteArray? = null,
        frameStdin: Boolean = false,
        onProcess: ((Process) -> Unit)? = null,
    ): Int = runInterruptible {
        val process = builder.start()
        synchronized(processes) { processes += process }
        if (stdin != null) {
            if (frameStdin) {
                /* 4-byte big-endian length + payload, stdin kept open for the
                 * status-record ACK channel. */
                runCatching {
                    val out = process.outputStream
                    val length = stdin.size
                    out.write(
                        byteArrayOf(
                            (length ushr 24).toByte(),
                            (length ushr 16).toByte(),
                            (length ushr 8).toByte(),
                            length.toByte(),
                        ),
                    )
                    out.write(stdin)
                    out.flush()
                }
            } else {
                runCatching { process.outputStream.use { it.write(stdin) } }
            }
        }
        onProcess?.invoke(process)
        val reader = if (captureOutput) Thread {
            try {
                process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines -> lines.forEach(onLog) }
            } catch (_: IOException) {
            }
        }.apply {
            name = "process-output-reader"
            isDaemon = true
        } else null
        try {
            reader?.start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            reader?.let(::joinReader)
            if (finished) process.exitValue() else -1
        } finally {
            if (process.isAlive) process.destroyForcibly()
            reader?.interrupt()
            runCatching { process.inputStream.close() }
            reader?.let(::joinReader)
            synchronized(processes) { processes -= process }
        }
    }

    private fun joinReader(reader: Thread) {
        try {
            reader.join(3000)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun tailKsuLog(logFile: File, offset: AtomicLong, onLog: (String) -> Unit) {
        if (!logFile.isFile) return
        synchronized(offset) {
            runCatching {
                RandomAccessFile(logFile, "r").use { file ->
                    val position = offset.get().takeIf { it <= file.length() } ?: 0L
                    file.seek(position)
                    var lastComplete = position
                    val pending = StringBuilder()
                    while (true) {
                        val byte = file.read()
                        if (byte == -1) break
                        if (byte == '\n'.code) {
                            if (pending.isNotEmpty()) onLog(pending.toString())
                            pending.clear()
                            lastComplete = file.filePointer
                        } else {
                            pending.append(byte.toChar())
                        }
                    }
                    offset.set(lastComplete)
                }
            }
        }
    }

    private val processes = mutableSetOf<Process>()

}
