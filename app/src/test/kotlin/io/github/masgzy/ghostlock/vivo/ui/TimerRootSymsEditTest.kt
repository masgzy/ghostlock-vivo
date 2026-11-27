package io.github.masgzy.ghostlock.vivo.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The 编辑配置 page's field parsing and save path: essential geometry keys
 * come first, unknown off.* keys are ignored, and saving replaces only the
 * edited lines while the symbol table itself is preserved verbatim.
 */
class TimerRootSymsEditTest {

    private val table = """
        # ic-timer symbol table
        # build=6.1.145-android14-11-maybe-dirty
        __tracepoint_sys_exit=0xffffffc00a3c9ec0
        nf_logger=0xffffffc00a2d2ee0
        off.timer_alloc=0x108
        off.task_cred=0x6a8
        off.tp_funcs=0x40
        off.cred_alloc=0x200
        off.not_a_real_key=0x1
    """.trimIndent()

    @Test
    fun `fields list essential geometry first then optional`() {
        val fields = timerRootEditFieldsOf(table)
        val keys = fields.map { it.key }
        /* essential first (in TimerRootGeometry order), optional after */
        assertEquals(0, keys.indexOf("timer_alloc"))
        assertEquals(1, keys.indexOf("task_cred"))
        assertEquals(2, keys.indexOf("tp_funcs"))
        assertTrue(keys.indexOf("cred_alloc") > keys.indexOf("tp_funcs"))
        /* unknown off.* keys are dropped */
        assertTrue("not_a_real_key" !in keys)
        /* the hard target comes last */
        assertEquals(TimerRootHardTarget, keys.last())
        assertEquals("0xffffffc00a3c9ec0", fields.last().value)
    }

    @Test
    fun `save replaces only the edited lines`() {
        val fields = timerRootEditFieldsOf(table).map {
            if (it.key == "task_cred") it.copy(value = "0x6b0") else it
        }
        val saved = applyTimerRootEdits(table, fields)
        assertTrue(saved.contains("off.task_cred=0x6b0"))
        /* untouched lines survive verbatim */
        assertTrue(saved.contains("off.timer_alloc=0x108"))
        assertTrue(saved.contains("nf_logger=0xffffffc00a2d2ee0"))
        assertTrue(saved.contains("# build=6.1.145-android14-11-maybe-dirty"))
        assertTrue(saved.contains("__tracepoint_sys_exit=0xffffffc00a3c9ec0"))
        /* unknown keys stay as they were */
        assertTrue(saved.contains("off.not_a_real_key=0x1"))
    }

    @Test
    fun `empty edit value keeps the original line`() {
        val fields = timerRootEditFieldsOf(table).map {
            if (it.key == "tp_funcs") it.copy(value = "") else it
        }
        val saved = applyTimerRootEdits(table, fields)
        /* A blanked field must not wipe the line — that would silently drop
         * geometry the loader needs. */
        assertTrue(saved.contains("off.tp_funcs=0x40"))
    }

    @Test
    fun `hard target edit round trips`() {
        val fields = timerRootEditFieldsOf(table).map {
            if (it.key == TimerRootHardTarget) it.copy(value = "0xffffffc00a3c9000") else it
        }
        val saved = applyTimerRootEdits(table, fields)
        assertTrue(saved.contains("__tracepoint_sys_exit=0xffffffc00a3c9000"))
        val reparsed = timerRootEditFieldsOf(saved)
        assertEquals("0xffffffc00a3c9000", reparsed.last().value)
    }
}
