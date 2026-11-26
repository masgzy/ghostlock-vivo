package com.ghostlock.app.data

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

/** Covers the platform-facing scan(): package enumeration, self/system
 * filtering, and libksud.so detection through a real PackageManager. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ManagerScannerScanTest {
    private lateinit var pm: PackageManager
    private lateinit var app: Application

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication() as Application
        pm = app.packageManager
    }

    private fun install(pkg: String, system: Boolean, ksud: Boolean, daemonLib: String = "libksud.so") {
        // Each package gets its own lib dir so ksud/apd presence is independent.
        val dir = File(app.cacheDir, "libs-${pkg}-${System.nanoTime()}").apply { mkdirs() }
        val info = ApplicationInfo().apply {
            packageName = pkg
            flags = if (system) ApplicationInfo.FLAG_SYSTEM else 0
            nativeLibraryDir = dir.absolutePath
        }
        if (ksud) File(dir, daemonLib).writeText("stub")
        shadowOf(pm).installPackage(
            PackageInfo().apply {
                packageName = pkg
                applicationInfo = info
            },
        )
    }

    /** Mirrors SukiSU Nova's release build: the daemon ships as a randomly
     * named .so that carries the family-wide ksud log signature. */
    private fun installRandomizedKsud(pkg: String, otherLibs: List<String> = emptyList()) {
        val dir = File(app.cacheDir, "libs-${pkg}-${System.nanoTime()}").apply { mkdirs() }
        val info = ApplicationInfo().apply {
            packageName = pkg
            flags = 0
            nativeLibraryDir = dir.absolutePath
        }
        // The JNI glue library: contains the bare execl argument string but
        // not the late-load log sentence.
        File(dir, "libqvbfhpwxrj.so").writeText("execl path ksud late-load --magica")
        otherLibs.forEach { File(dir, it).writeText("filler") }
        File(dir, "libksudqxwvbfn.so").writeBytes(
            ByteArray(1024) +
                "late-load command triggered!".toByteArray() +
                ByteArray(1024),
        )
        shadowOf(pm).installPackage(
            PackageInfo().apply {
                packageName = pkg
                applicationInfo = info
            },
        )
    }

    @Test
    fun `scan keeps user apps and drops self and system apps`() {
        install("me.weishu.kernelsu", system = false, ksud = true)
        install("me.bmax.apatch", system = false, ksud = true, daemonLib = "libapd.so")
        install("com.example.no-ksud", system = false, ksud = false)
        install("com.android.settings", system = true, ksud = false)

        val result = ManagerScanner.scan(pm, "com.ghostlock.app")
        // User apps without libksud/libapd stay visible for the show-all section.
        assertEquals(
            listOf("me.bmax.apatch", "me.weishu.kernelsu", "com.example.no-ksud"),
            result.map { it.packageName },
        )
        assertTrue(result[0].hasKsud)
        assertTrue(result[0].builtin)
        assertTrue(result[1].hasKsud)
        assertTrue(result[1].builtin)
        assertFalse(result[2].hasKsud)
    }

    @Test
    fun `scan drops the self package even if it ships libksud`() {
        install("com.ghostlock.app", system = false, ksud = true)
        assertTrue(ManagerScanner.scan(pm, "com.ghostlock.app").isEmpty())
    }

    @Test
    fun `scan reports hasKsud false when the lib dir is empty`() {
        install("com.example.bare", system = false, ksud = false)
        val result = ManagerScanner.scan(pm, "com.ghostlock.app")
        assertEquals(1, result.size)
        assertFalse(result[0].hasKsud)
        assertFalse(result[0].builtin)
    }

    @Test
    fun `scan detects SukiSU Nova's randomized ksud by content`() {
        installRandomizedKsud("com.sukisu.nova")
        val result = ManagerScanner.scan(pm, "com.ghostlock.app")
        assertEquals(listOf("com.sukisu.nova"), result.map { it.packageName })
        assertTrue(result[0].hasKsud)
        assertTrue(result[0].builtin)
    }

    @Test
    fun `randomized lib names alone do not mark a package as ksud provider`() {
        // A non-scanned package shipping the same randomized layout is not
        // content-probed, matching the previous name-only contract.
        installRandomizedKsud("com.example.clone")
        val result = ManagerScanner.scan(pm, "com.ghostlock.app")
        assertEquals(1, result.size)
        assertFalse(result[0].hasKsud)
    }
}
