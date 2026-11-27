package io.github.masgzy.ghostlock.vivo.data

import io.github.masgzy.ghostlock.vivo.domain.model.TimerRootGeometry

/**
 * Pure parser for the extended ic-syms table (the TimerRoot / CVE-2026-98260
 * chain's "98260 配置").
 *
 * Format (third_party/timerroot/ic_syms.{c,h} is the contract):
 * ```
 * # ic-timer symbol table
 * # build=<uname -r of the image the table was parsed from>
 * __tracepoint_sys_exit=0xffffffc00a3c9ec0
 * ...                                        # name=0xADDR symbol lines
 * # geometry (BTF-derived; consumed by the TimerRoot core)
 * off.timer_alloc=0x108                      # off.<field>=0xVALUE geometry
 * ...
 * ```
 *
 * The geometry block is what lets the generic libtimerroot.so run on a
 * kernel outside its compiled profile. See [TimerRootGeometry] for the
 * essential key set (16 keys).
 */
object TimerRootTable {

    data class Summary(
        /** `# build=` banner (the kernel the table was parsed from). */
        val release: String? = null,
        /** Count of `name=0xADDR` symbol lines. */
        val symbols: Int = 0,
        /** Count of recognized `off.*` lines. */
        val geometryKeys: Int = 0,
        /** How many essential keys (of [TimerRootGeometry.ESSENTIAL_COUNT]) are present. */
        val geometryEssential: Int = 0,
        /** The hard target the C loader requires to use a table at all. */
        val hasTracepointTarget: Boolean = false,
    ) {
        val hasGeometry: Boolean get() = geometryKeys > 0
        val geometryComplete: Boolean get() = geometryEssential >= TimerRootGeometry.ESSENTIAL_COUNT
    }

    fun summarize(text: String): Summary {
        var release: String? = null
        var symbols = 0
        var geometryKeys = 0
        var geometryEssential = 0
        var hasTracepointTarget = false
        text.lineSequence().forEach { rawLine ->
            val line = rawLine.trimEnd('\r', '\n')
            when {
                line.startsWith("# build=") && release == null ->
                    release = line.removePrefix("# build=").trim().takeIf { it.isNotEmpty() }

                line.startsWith("off.") -> {
                    val key = line.substringAfter("off.").substringBefore('=')
                    if (key in TimerRootGeometry.KNOWN_KEYS) {
                        geometryKeys++
                        if (key in TimerRootGeometry.ESSENTIAL_KEYS) geometryEssential++
                    }
                }

                !line.startsWith('#') && line.contains("=0x") -> {
                    symbols++
                    if (line.startsWith("__tracepoint_sys_exit=")) hasTracepointTarget = true
                }
            }
        }
        return Summary(
            release = release,
            symbols = symbols,
            geometryKeys = geometryKeys,
            geometryEssential = geometryEssential,
            hasTracepointTarget = hasTracepointTarget,
        )
    }
}
