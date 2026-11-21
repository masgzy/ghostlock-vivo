package com.ghostlock.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.ghostlock.app.data.ManagerScanner
import com.ghostlock.app.data.NativeProfileDocument
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

@Keep
class GhostlockUserService(private val context: Context) : IGhostlockUserService.Stub() {
    private val running = AtomicBoolean(false)

    private companion object {
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"
    }

    override fun runExploit(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) = runExploitAsManager(primaryCpu, consumerCpu, safeMode, forceAttack, profileBlob, debugDir, null, callback, statusCallback)

    override fun runExploitAsManager(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        managerPackage: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                require(profileBlob.size >= 16) { "profile blob is too short" }
                // PROFILE-SUGGEST-01: recommend_shizuku is a suggestion; the
                // blob's meta section carries it, and the app already chose the
                // Shizuku path, so it is logged, never a gate.
                if (NativeProfileDocument.fromBinary(profileBlob)?.recommendShizuku != 1u) {
                    callback.onLog("<s> kernel does not require Shizuku; running on user request")
                }

                val binary = File(context.applicationInfo.nativeLibraryDir, "libghostlock.so")
                require(binary.isFile) { "missing GhostLock binary: ${binary.absolutePath}" }

                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("<s> Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("<s> kernel: $release")
                // Same resolution as the direct path: chosen manager first,
                // then the built-ins; name-randomized managers (SukiSU Nova)
                // fall back to the content probe. Native gets the path via
                // GHOSTLOCK_KSUD.
                val pm = context.packageManager
                val ksudPath = ManagerScanner.resolvePackages(managerPackage)
                    .asSequence()
                    .mapNotNull { pkg ->
                        val dir = runCatching {
                            pm.getApplicationInfo(pkg, 0).nativeLibraryDir
                        }.getOrNull() ?: return@mapNotNull null
                        File(dir, "libksud.so").takeIf { it.isFile }
                            ?: if (pkg in ManagerScanner.CONTENT_SCANNED) {
                                ManagerScanner.findKsudByContent(File(dir))
                            } else {
                                null
                            }
                    }
                    .firstOrNull()
                ksudPath?.let { callback.onLog("<s> ksud resolved: ${it.absolutePath}") }
                val nativeLog = File(workDir, ".ghostlock_native.log")
                // U01-S14: per-run KernelSU log so a previous run's markers can
                // never satisfy the handoff probe; the native process receives
                // the resolved path via GHOSTLOCK_KSU_LOG.
                val ksuLog = File(workDir, "ghostlock-ksu-${System.currentTimeMillis()}.log")
                // v2: safe_mode lives in the meta section; there is no fixed
                // slot offset, so the blob is rescanned and rewritten.
                val effectiveBlob = if (safeMode) {
                    NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                } else {
                    profileBlob
                }
                val argv = mutableListOf(
                    binary.absolutePath,
                    "--ghostlock-app-call",
                    "--enable-status-record",
                )
                if (forceAttack) {
                    argv += "--force-attack"
                }
                if (!debugDir.isNullOrEmpty()) {
                    argv += listOf("--dump-kernel-log", debugDir)
                }
                callback.onLog("<b> starting native: ${binary.absolutePath}")
                ProcessBuilder(argv)
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                        if (ksudPath != null) {
                            environment()["GHOSTLOCK_KSUD"] = ksudPath.absolutePath
                        }
                    }
                    .start()
                    .let { process ->
                        val stdinOut = process.outputStream
                        /* Length-prefixed GLK1; stdin stays open for the ACK. */
                        runCatching {
                            val length = effectiveBlob.size
                            stdinOut.write(
                                byteArrayOf(
                                    (length ushr 24).toByte(),
                                    (length ushr 16).toByte(),
                                    (length ushr 8).toByte(),
                                    length.toByte(),
                                ),
                            )
                            stdinOut.write(effectiveBlob)
                            stdinOut.flush()
                        }
                        // The native process writes its log to a file and this
                        // tailer forwards lines asynchronously. Reading a pipe
                        // here applied backpressure inside the PI race window
                        // (every line also costs a binder round trip), which
                        // stalled the route and ended in a kernel panic.
                        val tailer = Thread({
                            relayLog(nativeLog, callback, statusCallback, stdinOut)
                        }, "ghostlock-shizuku-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        val exitCode = process.waitFor()
                        callback.onLog("<b> native exited code=$exitCode")
                        Thread.sleep(200)
                        tailer.interrupt()
                        tailer.join(1000)
                        exitCode
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-runner").start()
    }

    /** Forward complete native log lines without ever blocking the native
     * process; the file is the transport, binder is only the display path. */
    /** Forwards status events to the app (persist) and ACKs the native process;
     *  returns true when the line was a status event. */
    private fun handleStatusLine(
        line: String,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            runCatching { statusCallback.onStatus("", "disabled") }
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size >= 2) {
            runCatching { statusCallback.onStatus(parts[0], parts[1]) }
            runCatching {
                stdinOut.write(StatusAck.toByteArray(Charsets.UTF_8))
                stdinOut.flush()
            }
        }
        return true
    }

    private fun relayLog(
        logFile: File,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) {
                                    if (!handleStatusLine(line, statusCallback, stdinOut)) {
                                        runCatching { callback.onLog(line) }
                                    }
                                }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    override fun destroy() {
        if (!running.get()) kotlin.system.exitProcess(0)
    }

    /* ---- TimerRoot (CVE-2026-98260) chain ------------------------------
     *
     * Contract reverse-engineered from the reference front-end
     * (com.ksu.cve98260 2.3.8, xxTurborocketxx/TimerRoot lineage): the
     * t98260 binary runs in the shell domain (it needs tracefs), escalates
     * on its own, then hands root to KernelSU via the ksud late-load. All
     * artifacts live in this service's workDir so the shell side never has
     * to read the app's 0700 data dir (the reference app points IC_HOME at
     * its filesDir and relies on root having been reached by then; keeping
     * everything under /data/local/tmp avoids that ordering entirely).
     */

    private fun timerRootWorkDir(): File =
        File("/data/local/tmp/ghostlock-app").apply { mkdirs() }

    /** Chunked upload of a user-provided t98260 binary (binder caps a
     * single transaction at ~1 MB; the exploit is ~2.4 MB). */
    override fun pushTimerRootBinary(chunk: ByteArray, offset: Int, total: Int) {
        try {
            val work = timerRootWorkDir()
            val staged = File(work, "t98260-user")
            if (offset == 0) staged.delete()
            require(offset == staged.length().toInt()) {
                "push out of order: have ${staged.length()}, got offset $offset"
            }
            require(offset + chunk.size <= total) { "push exceeds declared total $total" }
            FileOutputStream(staged, true).use { it.write(chunk) }
            if (staged.length().toInt() == total) {
                staged.setExecutable(true, false)
                staged.setReadable(true, false)
            }
        } catch (_: Exception) {
            /* The next run's preflight reports the mismatch; the push API
             * stays fire-and-forget like the rest of the Shizuku surface. */
        }
    }

    override fun runTimerRoot(
        managerApk: String?,
        ksudEntry: String?,
        symsTable: String?,
        safeMode: Boolean,
        allowAnyKernel: Boolean,
        callback: IGhostlockCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<t> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                callback.onLog("<t> TimerRoot chain: kernel=$release")
                val work = timerRootWorkDir()
                val exploit = stageTimerRootBinary(work, callback)

                // ksud: an explicit library choice wins; otherwise the same
                // resolution order as the GhostLock chain (chosen manager,
                // built-ins, content probe for name-randomized managers).
                val ksud = stageKsud(work, managerApk, ksudEntry, callback)

                // ic-syms table for builds outside the binary's built-ins.
                var symsFile: File? = null
                if (!symsTable.isNullOrEmpty()) {
                    symsFile = File(work, "ic-syms.txt")
                    symsFile.writeText(symsTable)
                    callback.onLog("<t> ic-syms table staged (${symsTable.length} bytes)")
                }

                val handoff = File(work, "ghostlock-ksu.sh")
                handoff.writeText(timerRootHandoffScript(work.absolutePath, safeMode))
                handoff.setExecutable(true, false)

                val log = File(work, "ic.log")
                log.delete()
                val env = buildMap<String, String> {
                    put("IC_HOME", work.absolutePath)
                    put("T28_NO_HOLD", "1")
                    put("IC_PLANT_ATTEMPTS", "32")
                    put("IC_DISCOVER_ATTEMPTS", "16")
                    put("IC_DISCOVER_WAIT_MS", "1000")
                    put("IC_EXEC_PAYLOAD", "1")
                    put("HOME", work.absolutePath)
                    put("TMPDIR", work.absolutePath)
                    symsFile?.let { put("IC_SYMS_FILE", it.absolutePath) }
                    ksud?.let { put("IC_KSUD", it.absolutePath) }
                    /* IC_ALLOW_ANY_KERNEL: run an imported t98260 whose built-in
                     * profile targets a different kernel. The staged ic-syms
                     * table supplies this boot's slide, so the writes stay
                     * aimed; without a table this is a blind override and the
                     * log says so. */
                    if (allowAnyKernel) {
                        put("IC_ALLOW_ANY_KERNEL", "1")
                        callback.onLog(
                            "<t> IC_ALLOW_ANY_KERNEL=1: profile gate bypassed" +
                                if (symsFile != null) " (slide from the staged ic-syms table)"
                                else " (WARNING: no ic-syms table staged, the slide is guessed)",
                        )
                    }
                }
                callback.onLog("<t> launching t98260 (ksu mode)")
                val process = ProcessBuilder(
                    listOf(exploit.absolutePath, "ksu"),
                )
                    .directory(work)
                    .redirectErrorStream(true)
                    .redirectOutput(log)
                    .apply { environment().putAll(env) }
                    .start()
                val tailer = Thread({
                    relayFile(log, callback)
                }, "timerroot-tailer").apply { isDaemon = true; start() }
                val code = process.waitFor()
                Thread.sleep(300)
                tailer.interrupt()
                tailer.join(1000)
                callback.onLog("<t> t98260 exited code=$code")
                code
            }.getOrElse { error ->
                runCatching { callback.onLog("<t> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "timerroot-runner").start()
    }

    /** Staging precedence, mirrored by timerRootState(): the user-pushed
     * (imported) binary wins — an explicit choice — then the CI-built
     * generic libtimerroot.so from the APK's jniLibs, then the legacy
     * assets/t98260 dev asset. */
    private fun stageTimerRootBinary(work: File, callback: IGhostlockCallback): File {
        val target = File(work, "t98260")
        val pushed = File(work, "t98260-user")
        if (pushed.isFile && pushed.length() > 0) {
            pushed.copyTo(target, overwrite = true)
            target.setExecutable(true, false)
            callback.onLog("<t> t98260: user-provided (${pushed.length()} bytes)")
            return target
        }
        val library = File(context.applicationInfo.nativeLibraryDir, "libtimerroot.so")
        if (library.isFile && library.length() > 0) {
            library.copyTo(target, overwrite = true)
            target.setExecutable(true, false)
            callback.onLog(
                "<t> t98260: bundled libtimerroot.so (${library.length()} bytes, " +
                    "config-driven; kernel profile from the staged table)",
            )
            return target
        }
        val fromAsset = runCatching {
            context.assets.open("t98260").use { input ->
                FileOutputStream(target).use { output -> input.copyTo(output) }
            }
            target.setExecutable(true, false)
            true
        }.getOrDefault(false)
        if (fromAsset && target.length() > 0) {
            callback.onLog("<t> t98260: embedded asset (${target.length()} bytes)")
            return target
        }
        error(
            "t98260 binary is missing: the APK bundles no libtimerroot.so, " +
                "carries no assets/t98260 and no user binary was imported. " +
                "Import one in the TimerRoot config screen first.",
        )
    }

    /** Extracts the chosen .so from the manager APK, or resolves the usual way. */
    private fun stageKsud(
        work: File,
        managerApk: String?,
        ksudEntry: String?,
        callback: IGhostlockCallback,
    ): File? {
        val target = File("/data/local/tmp/ksud")
        if (!managerApk.isNullOrEmpty() && !ksudEntry.isNullOrEmpty()) {
            val code = ProcessBuilder(
                "sh", "-c",
                "unzip -p '$managerApk' '$ksudEntry' > '${target.absolutePath}' && " +
                    "chmod 755 '${target.absolutePath}'",
            ).redirectErrorStream(true).start().waitFor()
            if (code == 0 && target.isFile && target.length() > 0) {
                callback.onLog("<t> ksud: $ksudEntry extracted from manager APK")
                return target
            }
            callback.onLog("<t> warning: chosen ksud entry extract failed; falling back to auto resolution")
        }
        val pm = context.packageManager
        val resolved = ManagerScanner.resolvePackages(null)
            .asSequence()
            .mapNotNull { pkg ->
                val dir = runCatching {
                    pm.getApplicationInfo(pkg, 0).nativeLibraryDir
                }.getOrNull() ?: return@mapNotNull null
                File(dir, "libksud.so").takeIf { it.isFile }
                    ?: if (pkg in ManagerScanner.CONTENT_SCANNED) {
                        ManagerScanner.findKsudByContent(File(dir))
                    } else {
                        null
                    }
            }
            .firstOrNull() ?: return null
        resolved.copyTo(target, overwrite = true)
        target.setExecutable(true, false)
        callback.onLog("<t> ksud resolved: ${resolved.absolutePath}")
        return target
    }

    /** Forwards a growing log file to the app without blocking the exploit. */
    private fun relayFile(logFile: File, callback: IGhostlockCallback) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) {
                                    runCatching { callback.onLog(line) }
                                }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(150)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    /**
     * The KernelSU handoff the root child executes after the escalation
     * (IC_EXEC_PAYLOAD=1). Mirrors the reference front-end's script: install
     * ksud to /data/adb/ksud, relax SELinux to permissive, late-load the
     * kernelsu module for this KMI, start the daemon, then log the marker
     * the app watches for. HOME_DIR is this service's workDir.
     */
    private fun timerRootHandoffScript(homeDir: String, safeMode: Boolean): String {
        return buildString {
            append("#!/system/bin/sh\n")
            append("HOME_DIR='").append(homeDir).append("'\n")
            append("LOG=\"\$HOME_DIR/ksu-load.log\"\n")
            append("KSUD=\"\$HOME_DIR/ksud\"\n")
            append("[ -x \"\$KSUD\" ] || KSUD=/data/local/tmp/ksud\n")
            append("[ -x \"\$KSUD\" ] || KSUD=/data/adb/ksud\n")
            append("echo \"[*] uid=\$(id -u) ksud=\$KSUD\" >>\"\$LOG\"\n")
            append("chmod 644 \"\$LOG\" 2>/dev/null\n")
            append("if [ -x \"\$KSUD\" ] && [ \"\$KSUD\" != /data/adb/ksud ]; then\n")
            append("  mkdir -p /data/adb 2>/dev/null\n")
            append("  cp -f \"\$KSUD\" /data/adb/ksud 2>/dev/null && chmod 755 /data/adb/ksud 2>/dev/null && \\\n")
            append("    echo \"[+] ksud installed -> /data/adb/ksud\" >>\"\$LOG\"\n")
            append("fi\n")
            append("echo 0 > /sys/fs/selinux/checkreqprot 2>/dev/null\n")
            append("KVER=\$(uname -r | cut -d. -f1-2)\n")
            append("AVER=\$(uname -r | grep -o 'android[0-9]*' | head -1)\n")
            append("KMI=\"\$AVER-\$KVER\"\n")
            if (safeMode) {
                append("echo \"[*] safe mode: disabling modules\" >>\"\$LOG\"\n")
                append("for m in /data/adb/modules/*/; do touch \"\$m/disable\" 2>/dev/null; done\n")
            }
            append("if grep -q '^kernelsu[[:space:]]' /proc/modules 2>/dev/null; then\n")
            append("  echo \"[*] kernelsu already loaded\" >>\"\$LOG\"\n")
            append("else\n")
            append("  [ -x \"\$KSUD\" ] || { echo '[!] ksud missing' >>\"\$LOG\"; exit 1; }\n")
            append("  \"\$KSUD\" late-load --kmi \"\$KMI\" >>\"\$LOG\" 2>&1\n")
            append("  echo \"[*] late-load exit=\$?\" >>\"\$LOG\"\n")
            append("fi\n")
            append("if ! pgrep -f ksud >/dev/null 2>&1; then\n")
            append("  \"\$KSUD\" --daemon >>\"\$LOG\" 2>&1 &\n")
            append("  sleep 2\n")
            append("fi\n")
            append("pgrep -f ksud >/dev/null 2>&1 && echo \"[+] ksud daemon running\" >>\"\$LOG\" || \\\n")
            append("  echo '[!] ksud daemon not running' >>\"\$LOG\"\n")
            append("echo \"[+] KernelSU module loaded\" >>\"\$LOG\"\n")
        }
    }
}
