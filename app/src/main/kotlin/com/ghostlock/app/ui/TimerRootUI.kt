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
import top.yukonga.miuix.kmp.basic.TextFieldDefaults
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.RadioButtonLocation
import top.yukonga.miuix.kmp.preference.RadioButtonPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * TimerRoot (CVE-2026-98260) 配置 — 多级菜单，与 GhostLock 的「参数配置」
 * （ParameterScreen）同构：加载配置 / 编辑配置 / 配置文档（占位）/ 导出配置，
 * 再加上 98260 的专属设置（导入二进制、允许任意内核）。
 *
 * Layout parity with ParameterScreen: page content padding carries the side
 * margins, items sit in plain cards separated by the LazyColumn spacing —
 * no per-item padding on top of the page gutter (the double-gap look), and
 * full-width buttons keep the same side margins as the cards.
 *
 * The chain's "profile" is the staged extended ic-syms table: symbols plus the
 * BTF-derived off.* geometry block. It is produced by the same parsing pipeline
 * as the GhostLock offsets, imported as a ready-made file, or edited by hand.
 */
@Composable
internal fun TimerRootConfigScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
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
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            /* ---- 已加载状态横幅 ---------------------------------- */
            item(key = "loaded") {
                ProfileHintBanner(
                    text = if (state.timerRootSymsRelease != null) {
                        stringResource(
                            R.string.timerroot_loaded_banner,
                            state.timerRootSymsRelease,
                        )
                    } else {
                        stringResource(R.string.timerroot_syms_missing)
                    },
                )
            }

            item(key = "load") {
                Card {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_load_config),
                        summary = stringResource(R.string.timerroot_load_config_summary),
                        onClick = actions::onOpenTimerRootLoadConfig,
                    )
                }
            }
            if (state.timerRootSymsRelease != null) {
                item(key = "edit") {
                    Card {
                        ArrowPreference(
                            title = stringResource(R.string.timerroot_edit_config),
                            summary = stringResource(R.string.timerroot_edit_config_summary),
                            onClick = actions::onOpenTimerRootEdit,
                        )
                    }
                }
            }
            item(key = "docs") {
                Card {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_config_docs),
                        summary = stringResource(R.string.timerroot_config_docs_summary),
                        onClick = actions::onOpenTimerRootDocs,
                    )
                }
            }
            if (state.timerRootSymsRelease != null) {
                item(key = "export") {
                    TextButton(
                        text = stringResource(R.string.timerroot_export_config),
                        onClick = actions::onExportTimerRootSyms,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            /* ---- 98260 专属设置 ---------------------------------- */
            item(key = "special-title") {
                SmallTitle(text = stringResource(R.string.timerroot_special_title))
            }
            item(key = "binary") {
                Card {
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
                        ArrowPreference(
                            title = stringResource(R.string.timerroot_import_binary),
                            summary = stringResource(R.string.timerroot_import_binary_summary),
                            onClick = actions::onPickTimerRootBinary,
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
            item(key = "allow-any") {
                Card {
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
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                )
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(12.dp).navigationBarsPadding())
            }
        }
    }
}

/**
 * TimerRoot 配置 → 加载配置 — mirrors the GhostLock「加载配置」page
 * (LoadConfigScreen) in both structure and spacing: import a ready-made
 * table, parse a full package (local or remote) or a local image
 * (payload.bin / boot.img), pick one of the archived tables explicitly
 * (指定加载), and show the currently staged table.
 */
@Composable
internal fun TimerRootLoadConfigScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.timerroot_load_config),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseTimerRootLoadConfig) {
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
        ) {
            item(key = "top-space") { Spacer(Modifier.height(12.dp)) }

            item(key = "import-syms") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_import_config),
                        summary = stringResource(R.string.timerroot_import_config_summary),
                        onClick = actions::onPickTimerRootSyms,
                    )
                }
            }
            item(key = "parse-full-package") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_parse_ota_zip),
                        summary = stringResource(R.string.timerroot_parse_ota_zip_summary),
                        onClick = actions::onParseTimerRootFullPackage,
                    )
                }
            }
            item(key = "parse-image") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_parse_image),
                        summary = stringResource(R.string.timerroot_parse_image_summary),
                        onClick = actions::onParseTimerRootImageSource,
                    )
                }
            }

            /* ---- 已保存的表（指定加载） ------------------------ */
            item(key = "tables-title") {
                SmallTitle(text = stringResource(R.string.timerroot_tables_title))
            }
            item(key = "tables-entry") {
                Card(modifier = Modifier.preferencePageItem()) {
                    ArrowPreference(
                        title = stringResource(R.string.timerroot_tables_entry),
                        summary = stringResource(R.string.timerroot_tables_entry_summary),
                        onClick = actions::onOpenTimerRootTablePicker,
                        endActions = {
                            if (state.timerRootTables.isNotEmpty()) {
                                Text(
                                    text = state.timerRootTables.size.toString(),
                                    fontSize = 14.sp,
                                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                )
                            }
                        },
                    )
                }
            }
            if (state.timerRootTables.isEmpty()) {
                item(key = "tables-empty") {
                    ProfileHintBanner(
                        text = stringResource(R.string.timerroot_tables_empty),
                        modifier = Modifier.preferencePageItem(),
                    )
                }
            }

            /* ---- 已加载的表 ---------------------------------- */
            item(key = "staged-title") {
                SmallTitle(text = stringResource(R.string.timerroot_staged_title))
            }
            if (state.timerRootSymsRelease == null) {
                item(key = "staged-empty") {
                    ProfileHintBanner(
                        text = stringResource(R.string.timerroot_staged_empty),
                        modifier = Modifier.preferencePageItem(),
                    )
                }
            } else {
                item(key = "staged") {
                    Card(modifier = Modifier.preferencePageItem()) {
                        Column {
                            ArrowPreference(
                                title = state.timerRootSymsRelease,
                                summary = stringResource(
                                    R.string.timerroot_syms_stats,
                                    state.timerRootSymsSymbols,
                                    state.timerRootSymsGeometryEssential,
                                    state.timerRootSymsGeometryKeys,
                                ),
                                onClick = actions::onOpenTimerRootEdit,
                                endActions = {
                                    Text(
                                        text = stringResource(
                                            if (state.timerRootSymsGeometryEssential >= 16) {
                                                R.string.timerroot_geometry_complete_badge
                                            } else {
                                                R.string.timerroot_geometry_partial_badge
                                            },
                                        ),
                                        fontSize = 14.sp,
                                        fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                                        color = if (state.timerRootSymsGeometryEssential >= 16) {
                                            OverrideHighlight
                                        } else {
                                            FieldErrorHighlight
                                        },
                                    )
                                },
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
                        }
                    }
                }
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(24.dp).navigationBarsPadding())
            }
        }
    }
}

/**
 * TimerRoot 配置 → 加载配置 → 指定加载 — radio list of the archived tables,
 * mirroring the GhostLock「加载内置配置」picker (BuiltinProfileScreen): the
 * device kernel stays pinned on top, "自动" stages the archive matching it,
 * and every archived table is one explicit choice. Selection is derived from
 * the staged table's banner (content comparison, no persisted preference):
 * the auto row reads as selected whenever the staged table is what auto
 * would stage — the device kernel's own archive or nothing.
 */
@Composable
internal fun TimerRootTablePickerScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    val deviceKernel = state.kernelRelease
    val staged = state.timerRootSymsRelease
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.timerroot_tables_entry),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseTimerRootTablePicker) {
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
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(
                paddingValues, top = 0.dp, bottom = 0.dp, horizontalMin = 0.dp,
            ),
        ) {
            item(key = "top-space") { Spacer(Modifier.height(12.dp)) }
            item(key = "local-kernel") {
                ProfileHintBanner(
                    text = stringResource(R.string.local_kernel, deviceKernel),
                    modifier = Modifier.preferencePageItem(),
                )
            }
            item(key = "auto") {
                TimerRootTableRow(
                    title = stringResource(R.string.timerroot_table_auto),
                    summary = stringResource(R.string.timerroot_table_auto_summary),
                    selected = staged == null || staged == deviceKernel,
                    onClick = { actions.onSelectTimerRootTable(null) },
                    modifier = Modifier.preferencePageItem(),
                )
            }
            if (state.timerRootTables.isEmpty()) {
                item(key = "tables-empty") {
                    ProfileHintBanner(
                        text = stringResource(R.string.timerroot_tables_empty),
                        modifier = Modifier.preferencePageItem(),
                    )
                }
            } else {
                item(key = "tables-subtitle") {
                    SmallTitle(text = stringResource(R.string.timerroot_tables_subtitle))
                }
                items(state.timerRootTables.size, key = { "table:${state.timerRootTables[it].release}" }) { index ->
                    val table = state.timerRootTables[index]
                    TimerRootTableRow(
                        title = table.release,
                        summary = stringResource(
                            R.string.timerroot_syms_stats,
                            table.symbols,
                            table.geometryEssential,
                            table.geometryKeys,
                        ),
                        selected = staged == table.release && table.release != deviceKernel,
                        onClick = { actions.onSelectTimerRootTable(table.release) },
                        modifier = Modifier.preferencePageItem(),
                    )
                }
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(24.dp).navigationBarsPadding())
            }
        }
    }
}

/** One archived table row (radio at the end, like the builtin picker). */
@Composable
private fun TimerRootTableRow(
    title: String,
    summary: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth()) {
        RadioButtonPreference(
            title = title,
            summary = summary,
            selected = selected,
            onClick = onClick,
            radioButtonLocation = RadioButtonLocation.End,
        )
    }
}

/**
 * TimerRoot 配置 → 编辑配置 — the staged table's off.* geometry block and the
 * hard target symbol as text fields; everything else in the table is preserved
 * verbatim on save. Field layout mirrors the GhostLock parameter editor
 * (ExecutionEditor): bare text fields in the page gutter, no per-field card.
 * Save and revert are full-width buttons separated by the page spacing, like
 * the GhostLock editor's 保存 / 回退编辑 pair.
 */
@Composable
internal fun TimerRootEditScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.timerroot_edit_config),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseTimerRootEdit) {
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
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "info") {
                ProfileHintBanner(
                    title = state.timerRootSymsRelease
                        ?: stringResource(R.string.timerroot_edit_config),
                    text = stringResource(R.string.timerroot_edit_hint),
                )
            }

            item(key = "geometry-title") {
                SmallTitle(text = stringResource(R.string.timerroot_edit_geometry_title))
            }
            state.timerRootEditFields.withIndex().forEach { (index, field) ->
                item(key = "field-$index-${field.key}") {
                    TextField(
                        value = field.value,
                        onValueChange = { actions.onTimerRootFieldChanged(index, it) },
                        label = field.label,
                        colors = if (!isTimerRootHexField(field.value)) {
                            TextFieldDefaults.textFieldColors(labelColor = FieldErrorHighlight)
                        } else {
                            TextFieldDefaults.textFieldColors()
                        },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                }
            }

            item(key = "actions") {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(
                        text = stringResource(R.string.timerroot_edit_save),
                        onClick = actions::onSaveTimerRootEdits,
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    TextButton(
                        text = stringResource(R.string.timerroot_edit_revert),
                        onClick = actions::onRevertTimerRootEdits,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(12.dp).navigationBarsPadding())
            }
        }
    }
}

/** TimerRoot 配置 → 配置文档（占位，文档后续补充）。 */
@Composable
internal fun TimerRootDocsScreen(
    onBack: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.timerroot_config_docs),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "placeholder") {
                ProfileHintBanner(
                    title = stringResource(R.string.timerroot_docs_placeholder_title),
                    text = stringResource(R.string.timerroot_docs_placeholder_body),
                )
            }
            item(key = "notes") {
                Card {
                    Column {
                        Text(
                            text = stringResource(R.string.timerroot_docs_format_title),
                            style = MiuixTheme.textStyles.body2,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        )
                        Text(
                            text = stringResource(R.string.timerroot_docs_format_body),
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                    }
                }
            }
            item(key = "bottom-space") {
                Spacer(Modifier.height(12.dp).navigationBarsPadding())
            }
        }
    }
}

/** An editable 98260 value is hexadecimal, "0x108"-style; anything else is
 * marked in the editor and refused on save. */
internal fun isTimerRootHexField(value: String): Boolean =
    TimerRootHexRegex.matches(value.trim())

internal val TimerRootHexRegex = Regex("(0[xX])?[0-9a-fA-F]+")

private fun formatTimerRootSize(bytes: Long): String = when {
    bytes >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0)
    bytes >= 1024 -> "${bytes / 1024} KB"
    else -> "$bytes B"
}
