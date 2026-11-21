package com.ghostlock.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.app.R
import com.ghostlock.app.domain.model.TimerRootBinarySource
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * TimerRoot (CVE-2026-98260) 配置 — modelled after the GhostLock profile
 * screens. Reached from the main page ("TimerRoot 配置") and from Advanced
 * ("98260 配置", below 参数配置).
 *
 * The chain's "profile" is the staged extended ic-syms table: symbols plus
 * the BTF-derived off.* geometry block. It is produced by the same parsing
 * pipeline as the GhostLock offsets (full OTA package / boot.img /
 * payload.bin / OTA URL), or imported as a ready-made file, and can be
 * exported for sharing. The binary side is the bundled config-driven
 * libtimerroot.so, with an optional imported override.
 */
@Composable
internal fun TimerRootConfigScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    var otaUrl by remember { mutableStateOf("") }
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.timerroot_config_title),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseTimerRootConfig) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .imePadding()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(
                paddingValues, top = 0.dp, bottom = 0.dp, horizontalMin = 0.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "top-space") { Spacer(Modifier.height(12.dp)) }

            /* ---- status ------------------------------------------------ */
            item(key = "binary") {
                Card(modifier = Modifier.preferencePageItem()) {
                    Column {
                        val sourceText = stringResource(
                            when (state.timerRootBinarySource) {
                                TimerRootBinarySource.BUNDLED -> R.string.timerroot_binary_bundled
                                TimerRootBinarySource.EMBEDDED -> R.string.timerroot_binary_embedded
                                TimerRootBinarySource.IMPORTED -> R.string.timerroot_binary_imported
                                TimerRootBinarySource.MISSING -> R.string.timerroot_binary_missing
                            },
                        )
                        Text(
                            text = if (state.timerRootBinarySize > 0) {
                                "$sourceText (${formatTimerRootSize(state.timerRootBinarySize)})"
                            } else {
                                sourceText
                            },
                            style = MiuixTheme.textStyles.body2,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        )
                        if (state.timerRootBinarySource == TimerRootBinarySource.IMPORTED) {
                            ArrowPreference(
                                title = stringResource(R.string.timerroot_remove_binary),
                                summary = stringResource(R.string.timerroot_remove_binary_summary),
                                onClick = actions::onRemoveTimerRootBinary,
                            )
                        }
                    }
                }
            }
            item(key = "syms") {
                Card(modifier = Modifier.preferencePageItem()) {
                    Column {
                        ArrowPreference(
                            title = stringResource(R.string.timerroot_syms_title),
                            summary = state.timerRootSymsRelease
                                ?: stringResource(R.string.timerroot_syms_missing),
                            onClick = actions::onPickTimerRootSyms,
                        )
                        if (state.timerRootSymsRelease != null) {
                            Text(
                                text = stringResource(
                                    R.string.timerroot_syms_stats,
                                    state.timerRootSymsSymbols,
                                    state.timerRootSymsGeometryEssential,
                                    state.timerRootSymsGeometryKeys,
                                ),
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                            )
                            Text(
                                text = stringResource(
                                    if (state.timerRootSymsGeometryEssential >= 16) {
                                        R.string.timerroot_geometry_complete
                                    } else {
                                        R.string.timerroot_geometry_partial
                                    },
                                ),
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                            )
                            ArrowPreference(
                                title = stringResource(R.string.timerroot_export_syms),
                                summary = stringResource(R.string.timerroot_export_syms_summary),
                                onClick = actions::onExportTimerRootSyms,
                            )
                        }
                    }
                }
            }

            /* ---- parse (like the GhostLock offsets flow) ---------------- */
            item(key = "parse-title") {
                SmallTitle(text = stringResource(R.string.timerroot_parse_title))
            }
            item(key = "parse-ota-zip") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_parse_ota_zip),
                        summary = stringResource(R.string.timerroot_parse_ota_zip_summary),
                        onClick = actions::onPickTimerRootOta,
                    )
                }
            }
            item(key = "parse-image") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_parse_image),
                        summary = stringResource(R.string.timerroot_parse_image_summary),
                        onClick = actions::onPickTimerRootImage,
                    )
                }
            }
            item(key = "parse-url") {
                Card(modifier = Modifier.preferencePageItem()) {
                    Column {
                        Text(
                            text = stringResource(R.string.timerroot_parse_ota_url),
                            style = MiuixTheme.textStyles.body2,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                        TextField(
                            value = otaUrl,
                            onValueChange = { otaUrl = it },
                            label = stringResource(R.string.timerroot_parse_hint),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            singleLine = true,
                        )
                        TextButton(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            text = stringResource(R.string.timerroot_parse_button),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = { actions.onParseTimerRootSyms(otaUrl) },
                        )
                    }
                }
            }

            /* ---- import ------------------------------------------------ */
            item(key = "import-title") {
                SmallTitle(text = stringResource(R.string.timerroot_import_title))
            }
            item(key = "import-syms") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_import_syms),
                        summary = stringResource(R.string.timerroot_import_syms_summary),
                        onClick = actions::onPickTimerRootSyms,
                    )
                }
            }
            item(key = "import-binary") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_import_binary),
                        summary = stringResource(R.string.timerroot_import_binary_summary),
                        onClick = actions::onPickTimerRootBinary,
                    )
                }
            }

            /* ---- gate -------------------------------------------------- */
            item(key = "allow-any") {
                Card(modifier = Modifier.preferencePageItem()) {
                    SwitchPreference(
                        checked = state.timerRootAllowAnyKernel,
                        onCheckedChange = actions::onSetTimerRootAllowAnyKernel,
                        title = stringResource(R.string.timerroot_allow_any_kernel_label),
                        summary = stringResource(R.string.timerroot_allow_any_kernel_summary),
                    )
                }
            }

            item(key = "safety") {
                Text(
                    text = stringResource(R.string.timerroot_safety),
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    textAlign = TextAlign.Center,
                    fontSize = 13.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                )
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(24.dp).navigationBarsPadding())
            }
        }
    }
}

private fun formatTimerRootSize(bytes: Long): String = when {
    bytes >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0)
    bytes >= 1024 -> "${bytes / 1024} KB"
    else -> "$bytes B"
}
