package io.github.masgzy.ghostlock.vivo.data

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import io.github.masgzy.ghostlock.vivo.domain.model.KsudLibraryEntry
import java.io.File
import java.io.InputStream

/** Finds root-manager candidates and orders them for ksud resolution. */
object ManagerScanner {
    const val PREF_KEY = "manager_package"

    /** Built-in KernelSU-family, APatch and FolkPatch managers, priority order. */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.sukisu.ultra.pr",
        "com.sukisu.ultra",
        "com.sukisu.nova.pr",
        "com.sukisu.nova",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
        "me.bmax.apatch",
        "folk.zakodan",
        "me.yuki.folk",
    )

    /**
     * Managers that randomize the packaged ksud library name on every release
     * build, so `libksud.so` can never be matched by name. SukiSU Nova's CI
     * renames the daemon to `lib<random lowercase>.so` (and the JNI core to
     * another random name) to defeat detectors that pin stable anchors; only
     * the copies inside the APK change, the binary content does not. For these
     * packages the ksud library is located by a content signature instead.
     */
    val CONTENT_SCANNED = setOf(
        "com.sukisu.nova.pr",
        "com.sukisu.nova",
    )

    /**
     * Byte signature shared by every ksud build in the family (KernelSU,
     * SukiSU Ultra/Nova, ReSukiSU, BakaSU, KowSU, KernelSU Next, KiMiSU,
     * DiKSU): the Rust log line emitted by the late-load stage. It never
     * appears in the managers' other packaged libraries — the JNI glue lib
     * does contain the bare argument string "late-load" (it execl's the
     * daemon), but not this sentence.
     */
    private val KSUD_SIGNATURE = "late-load command triggered!".toByteArray(Charsets.UTF_8)

    /** Daemon libraries packaged by supported managers, checked in order. */
    private val DAEMON_LIBS = listOf("libksud.so", "libapd.so")

    /** First supported manager daemon binary in [nativeLibDir], name-based. */
    fun findDaemonBinary(nativeLibDir: String?): File? =
        nativeLibDir?.takeIf { it.isNotBlank() }?.let { dir ->
            DAEMON_LIBS.firstNotNullOfOrNull { File(dir, it).takeIf(File::isFile) }
        }

    /** Daemon binary for one package: name-based first, content scan for the
     * name-randomized managers. `null` when the package ships none. */
    fun findDaemonBinaryForPackage(packageName: String, nativeLibDir: String?): File? {
        findDaemonBinary(nativeLibDir)?.let { return it }
        if (nativeLibDir == null || packageName !in CONTENT_SCANNED) return null
        return findKsudByContent(File(nativeLibDir))
    }

    /** First manager daemon binary in [resolvePackages] order, or null. */
    fun resolveDaemonBinary(pm: PackageManager, chosen: String?): File? =
        resolvePackages(chosen).firstNotNullOfOrNull { pkg ->
            runCatching { pm.getApplicationInfo(pkg, 0).nativeLibraryDir }.getOrNull()
                ?.let { dir -> findDaemonBinaryForPackage(pkg, dir) }
        }

    /** True when [binary] is APatch's apd daemon (`libapd.so` / `apd`). */
    fun isApatch(binary: File?): Boolean =
        binary?.name == "libapd.so" || binary?.name == "apd"

    data class Candidate(
        val packageName: String,
        val label: String,
        val hasKsud: Boolean,
        val builtin: Boolean,
    )

    /**
     * All non-system apps, compatible first. Relies on QUERY_ALL_PACKAGES;
     * if that permission is ever dropped, filter to BUILTIN here.
     */
    @Suppress("DEPRECATION")
    fun scan(pm: PackageManager, selfPackage: String): List<Candidate> =
        pm.getInstalledPackages(0)
            .asSequence()
            .mapNotNull { pi -> pi.applicationInfo?.let { pi to it } }
            .filter { (pi, _) -> pi.packageName != selfPackage }
            .filter { (_, ai) -> (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            .map { (pi, ai) ->
                val dir = ai.nativeLibraryDir
                Candidate(
                    packageName = pi.packageName,
                    label = ai.loadLabel(pm).toString(),
                    hasKsud = hasKsud(pi.packageName, dir),
                    builtin = pi.packageName in BUILTIN,
                )
            }
            .sortedWith(sortComparator())
            .toList()

    /**
     * A manager provides a daemon when `libksud.so` / `libapd.so` exists
     * under its native library dir, or — for the name-randomized managers —
     * when one of the packaged `.so` files carries the ksud signature.
     */
    fun hasKsud(packageName: String, nativeLibraryDir: String?): Boolean =
        findDaemonBinaryForPackage(packageName, nativeLibraryDir) != null

    /**
     * Locates the ksud binary inside a native library dir whose packaged
     * name is randomized (SukiSU Nova). Every `.so` is probed for the
     * family-wide late-load log signature; ksud is several MB, so reads are
     * chunked instead of loading the whole file.
     */
    fun findKsudByContent(dir: File): File? {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".so") } ?: return null
        for (file in files) {
            if (file.containsSignature()) return file
        }
        return null
    }

    private fun File.containsSignature(): Boolean =
        runCatching { inputStream().use { it.hasSignature() } }.getOrDefault(false)

    private fun InputStream.hasSignature(): Boolean {
        val chunk = 64 * 1024
        val overlap = KSUD_SIGNATURE.size - 1
        val buffer = ByteArray(chunk + overlap)
        var kept = 0
        while (true) {
            val read = read(buffer, kept, chunk)
            if (read <= 0) break
            val window = kept + read
            if (indexOfSignature(buffer, window)) return true
            /* Carry the tail so a signature straddling the chunk edge matches;
             * a window shorter than the signature cannot hold one, so the
             * whole window is carried instead. */
            val carry = minOf(overlap, window)
            System.arraycopy(buffer, window - carry, buffer, 0, carry)
            kept = carry
        }
        return false
    }

    private fun indexOfSignature(buffer: ByteArray, length: Int): Boolean {
        val first = KSUD_SIGNATURE[0]
        val limit = length - KSUD_SIGNATURE.size
        var i = 0
        while (i <= limit) {
            if (buffer[i] == first && matchesAt(buffer, i)) return true
            i++
        }
        return false
    }

    private fun matchesAt(buffer: ByteArray, offset: Int): Boolean {
        for (i in KSUD_SIGNATURE.indices) {
            if (buffer[offset + i] != KSUD_SIGNATURE[i]) return false
        }
        return true
    }

    /**
     * Lists the executable `.so` entries under `lib/arm64-v8a/` of a manager
     * APK, with the content-signature flag set on the one our marker
     * identifies as ksud. Sorted by size descending (the daemon dwarfs every
     * glue library), mirroring the reference TimerRoot picker.
     */
    fun listApkLibraries(apkPath: String): List<KsudLibraryEntry> {
        val entries = runCatching {
            java.util.zip.ZipFile(apkPath).use { zip ->
                zip.entries().asSequence()
                    .filter { it.name.startsWith("lib/arm64-v8a/") && it.name.endsWith(".so") }
                    .map { it.name to it.size }
                    .toList()
            }
        }.getOrDefault(emptyList())
        return entries
            .sortedByDescending { it.second }
            .map { (name, size) ->
                KsudLibraryEntry(
                    zipPath = name,
                    sizeBytes = size,
                    detectedKsud = apkEntryHasSignature(apkPath, name),
                )
            }
    }

    private fun apkEntryHasSignature(apkPath: String, entry: String): Boolean =
        runCatching {
            java.util.zip.ZipFile(apkPath).use { zip ->
                zip.getInputStream(zip.getEntry(entry)).use { it.hasSignature() }
            }
        }.getOrDefault(false)

    /** Pure sort, extracted so it is testable without a PackageManager. */
    fun sortComparator() = compareByDescending<Candidate> { it.builtin && it.hasKsud }
        .thenByDescending { it.hasKsud }
        .thenBy { it.label.lowercase() }

    /** Chosen package first, then the rest of the built-ins in priority order. */
    fun resolvePackages(chosen: String?): List<String> =
        if (chosen.isNullOrBlank()) BUILTIN
        else listOf(chosen) + BUILTIN.filter { it != chosen }
}
