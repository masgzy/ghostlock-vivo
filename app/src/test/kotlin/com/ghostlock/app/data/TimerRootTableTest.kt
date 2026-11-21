package com.ghostlock.app.data

import com.ghostlock.app.domain.model.TimerRootGeometry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** TimerRootTable summarizes the extended ic-syms table the 98260 chain
 * stages as its "profile". */
class TimerRootTableTest {

    private val fullTable = """
        # ic-timer symbol table
        # build=6.1.145-android14-11-maybe-dirty
        __tracepoint_sys_exit=0xffffffc00a3c9ec0
        selinux_state=0xffffffc00a55a4f0
        init_user_ns=0xffffffc00a1f0f70
        init_cred=0xffffffc00a1cae08
        root_user=0xffffffc00a1f1208
        init_ucounts=0xffffffc00a1f2ab8
        init_groups=0xffffffc00a1f2528
        msleep=0xffffffc008123456
        # geometry (BTF-derived; consumed by the TimerRoot core)
        off.timer_alloc=0x108
        off.cred_req=0xb8
        off.task_alloc_bytes=0x1500
        off.task_cred=0x838
        off.cred_uid=0x8
        off.cap_inh=0x2c
        off.cap_perm=0x34
        off.cap_eff=0x3c
        off.cap_bset=0x44
        off.cap_amb=0x4c
        off.cred_security=0x78
        off.cred_user=0x80
        off.cred_user_ns=0x88
        off.cred_ucounts=0x90
        off.cred_group_info=0x98
        off.tp_funcs=0x40
        off.timer_node_off=0x78
    """.trimIndent()

    @Test
    fun fullTableIsComplete() {
        val summary = TimerRootTable.summarize(fullTable)
        assertEquals("6.1.145-android14-11-maybe-dirty", summary.release)
        assertEquals(8, summary.symbols)
        assertTrue(summary.hasTracepointTarget)
        assertEquals(17, summary.geometryKeys)
        assertEquals(TimerRootGeometry.ESSENTIAL_COUNT, summary.geometryEssential)
        assertTrue(summary.geometryComplete)
    }

    @Test
    fun legacyTableHasNoGeometry() {
        val summary = TimerRootTable.summarize(
            """
            # ic-timer symbol table
            # build=6.1.157-android14-11-gb3d4cdadf339
            __tracepoint_sys_exit=0xffffffc00a1b1da0
            init_cred=0xffffffc00a031aa8
            """.trimIndent(),
        )
        assertEquals("6.1.157-android14-11-gb3d4cdadf339", summary.release)
        assertEquals(2, summary.symbols)
        assertEquals(0, summary.geometryKeys)
        assertEquals(0, summary.geometryEssential)
        assertFalse(summary.hasGeometry)
        assertFalse(summary.geometryComplete)
    }

    @Test
    fun partialGeometryIsIncomplete() {
        val summary = TimerRootTable.summarize(
            fullTable
                .replace("off.cap_amb=0x4c\n", "")
                .replace("off.tp_funcs=0x40\n", "")
                .replace("off.cred_user_ns=0x88\n", ""),
        )
        assertEquals(14, summary.geometryKeys)
        assertEquals(TimerRootGeometry.ESSENTIAL_COUNT - 3, summary.geometryEssential)
        assertFalse(summary.geometryComplete)
    }

    @Test
    fun unknownGeometryKeysAreIgnored() {
        val summary = TimerRootTable.summarize(
            """
            # build=6.6.30-android16
            __tracepoint_sys_exit=0x1000
            off.nonsense=0x10
            off.cap_inh=0x28
            off.timer_alloc=0x120
            """.trimIndent(),
        )
        assertEquals("6.6.30-android16", summary.release)
        assertEquals(1, summary.symbols)
        assertEquals(2, summary.geometryKeys)
        assertEquals(2, summary.geometryEssential)
    }

    @Test
    fun emptyInputIsSafe() {
        val summary = TimerRootTable.summarize("")
        assertNull(summary.release)
        assertEquals(0, summary.symbols)
        assertEquals(0, summary.geometryKeys)
        assertFalse(summary.hasTracepointTarget)
    }

    @Test
    fun essentialSetMatchesTheContract() {
        // Mirrors ic_geo_keys[] (third_party/timerroot/ic_syms.c) and
        // collect_ic_geometry (tools/extract_rs/src/report.rs).
        assertEquals(16, TimerRootGeometry.ESSENTIAL_COUNT)
        assertEquals(23, TimerRootGeometry.KNOWN_KEYS.size)
        assertTrue(TimerRootGeometry.KNOWN_KEYS.containsAll(TimerRootGeometry.ESSENTIAL_KEYS))
    }
}
