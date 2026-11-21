package com.ghostlock.app.ui

import android.net.Uri
import androidx.core.net.toUri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ghostlock.app.R
import com.ghostlock.app.data.TimerRootTable
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExploitChain
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.LogTone
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileFieldNode
import com.ghostlock.app.domain.model.ShizukuStatus
import com.ghostlock.app.domain.model.TimerRootGeometry
import com.ghostlock.app.domain.repository.GhostlockRepository
import com.ghostlock.app.domain.repository.ProfileConfigController
import com.ghostlock.app.domain.usecase.FormatLogUseCase
import com.ghostlock.app.domain.usecase.ImportOffsetsUseCase
import com.ghostlock.app.domain.usecase.LoadKernelSnapshotUseCase
import com.ghostlock.app.domain.usecase.ParseSourceUseCase
import com.ghostlock.app.domain.usecase.ReadDocumentUseCase
import com.ghostlock.app.domain.usecase.RunExploitUseCase
import com.ghostlock.app.domain.usecase.SelectCpuPairUseCase
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface GhostlockEffect {
    data class PickDocument(val request: DocumentRequest) : GhostlockEffect
    data object PickDebugFolder : GhostlockEffect
    data class CreateProfileDocument(val suggestedName: String) : GhostlockEffect
    data class Share(val uri: String) : GhostlockEffect
    data class Toast(val resourceId: Int) : GhostlockEffect
    data class Clipboard(val text: String) : GhostlockEffect
    data class KeepScreenAwake(val enabled: Boolean) : GhostlockEffect
    data object OpenShizuku : GhostlockEffect
}

private const val OverwriteSummaryLimit = 12

enum class DocumentRequest {
    ImportOffsetsHocon, ImportOffsetsJson, BootImage, XblImage, PayloadImage, UefiImage,
    VendorBootImage, TimerRootBinary, TimerRootSyms, TimerRootOtaZip, TimerRootImage,
}

/** Options offered by the attachment step, in display order. The step is a
 * loop: every attached image returns to it, and its first item runs the parse
 * with whatever is staged. VENDOR_BOOT serves both the MediaTek physical-base
 * path and the vivo/iQOO vr.ko probe. */
private enum class AttachOption { START, XBL, UEFI, VENDOR_BOOT }

private enum class ParseDialogStage { Mode, Attach }

class GhostlockViewModel(
    private val repository: GhostlockRepository,
) : ViewModel() {
    private val effectChannel = Channel<GhostlockEffect>(Channel.BUFFERED)
    private val mutableState = MutableStateFlow(GhostlockUiState())
    private var initialized = false
    private var running = false
    private val loadKernelSnapshot = LoadKernelSnapshotUseCase(repository)
    private val selectCpuPairUseCase = SelectCpuPairUseCase(repository)
    private val importOffsetsUseCase = ImportOffsetsUseCase(repository)
    private val parseSourceUseCase = ParseSourceUseCase(repository)
    private val readDocumentUseCase = ReadDocumentUseCase(repository)
    private val runExploitUseCase = RunExploitUseCase(repository)
    private val formatLog = FormatLogUseCase()
    private val profileController get() = repository.profileController()

    val state = mutableState.asStateFlow()
    val effects = effectChannel.receiveAsFlow()

    private var kernelSnapshot: KernelSnapshot? = null
    private var pendingBootPath: String? = null
    private var pendingPayloadPath: String? = null
    private var pendingUrl: String? = null
    private var pendingXblPath: String? = null
    private var pendingUefiPath: String? = null
    private var pendingVendorBootPath: String? = null
    private var pendingAttachOptions: List<AttachOption> = emptyList()
    private var parseDialogStage = ParseDialogStage.Mode
    /* Queued vendor_boot request, shown once the current dialog closes. */
    private var vendorBootPromptPending = false
    private var vendorBootImported = false
    private var pendingConfirmation: PendingConfirmation? = null

    fun initialize() {
        if (initialized) return
        initialized = true
        repository.setShizukuStatusListener { refreshAccessStatus() }
        mutableState.update { it.copy(launchManagerOnSuccess = repository.launchManagerOnSuccess()) }
        viewModelScope.launch {
            refreshSnapshot()
            applyRecommendedShizuku()
            maybeSuggestShizukuForW3()
        }
    }

    private var recommendedShizukuApplied = false

    /**
     * Kernels that recommend Shizuku start with the toggle on at every launch;
     * a manual switch-off still applies for the rest of the session.
     */
    private fun applyRecommendedShizuku() {
        if (recommendedShizukuApplied) return
        recommendedShizukuApplied = true
        val snapshot = kernelSnapshot ?: return
        if (!snapshot.recommendShizuku || state.value.shizukuEnabled) return
        toggleShizuku(true)
    }

    private var w3HintChecked = false

    /**
     * The previous run's native log survives export settings; when it failed
     * at the W3 seccomp bypass in-process, suggest switching to Shizuku.
     */
    private suspend fun maybeSuggestShizukuForW3() {
        if (w3HintChecked) return
        w3HintChecked = true
        val step = runCatching { repository.lastRunStuckStep() }.getOrNull() ?: return
        if (state.value.shizukuEnabled) return
        /* Any interrupted step is reported; only a W3 stall offers Shizuku,
         * because Shizuku (shell uid, no seccomp) skips exactly that stage. */
        val isW3 = step.startsWith("w3")
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = if (isW3) DialogType.CONFIRM else DialogType.NOTICE,
                dialogTitleRes = if (isW3) {
                    R.string.w3_shizuku_hint_title
                } else {
                    R.string.run_interrupted_title
                },
                dialogMessageRes = if (isW3) {
                    R.string.w3_shizuku_hint_message
                } else {
                    R.string.run_interrupted_message
                },
            )
        }
    }

    fun refreshAccessStatus() {
        if (initialized) viewModelScope.launch { refreshSnapshot() }
    }

    /* profile-ui: the controller owns loading, merging and persistence. */
    fun loadExecutionProfile(preserveEditing: Boolean = false) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            applyExecutionConfig(profileController.load(snapshot.kernelRelease, pair), preserveEditing)
        }
    }

    private fun applyExecutionConfig(config: ProfileConfig, preserveEditing: Boolean) {
        mutableState.update { state ->
            state.copy(
                executionRelease = config.release,
                executionHasProfile = config.hasProfile,
                executionFields = config.general,
                executionEditing = if (preserveEditing) state.executionEditing
                else config.general.associate { field -> field.path to field.value.toString() },
                profileInvalidPaths = config.invalidPaths,
                profileRoute = config.route,
                profileFallback = config.fallbackTo,
                activeBuiltinProfile = profileController.activeBuiltinRelease(),
                activeUserProfile = profileController.activeUserProfile(),
                customCpuPair = customCpuPairOf(config),
            )
        }
    }

    /** The pair actually resolved from the profile, when it beats the device pick. */
    private fun customCpuPairOf(config: ProfileConfig): CpuPair? {
        val snapshot = kernelSnapshot ?: return null
        val main = config.general
            .firstOrNull { it.path == "execution.selected_cpus.main" }?.value ?: return null
        val consumer = config.general
            .firstOrNull { it.path == "execution.selected_cpus.consumer" }?.value ?: return null
        val pair = CpuPair(main.toInt(), consumer.toInt())
        return pair.takeIf { it != snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) }
    }

    /** Route edits are draft-only; saving the session commits them. */
    fun onRouteChanged(index: Int) {
        val route = ProfileConfig.Routes.getOrNull(index - 1)
        if (route == state.value.profileRoute) return
        mutableState.update { it.copy(profileRoute = route) }
    }

    /** index 0 disables the fallback; the rest map to ProfileConfig.Routes. */
    fun onFallbackChanged(index: Int) {
        val fallback = if (index <= 0) "none" else ProfileConfig.Routes.getOrNull(index - 1)
        val current = state.value.profileFallback
        if (fallback == current || (fallback == "none" && current == null)) return
        mutableState.update { it.copy(profileFallback = fallback) }
    }

    /** General edits are draft-only; saving the session commits them. */
    fun updateExecutionField(path: String, value: String) {
        mutableState.update {
            it.copy(
                executionEditing = it.executionEditing + (path to value),
            )
        }
    }

    /* advanced-ui: the merged screen loads its editors and debug prefs. */
    fun onOpenAdvanced() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = true,
                aboutVisible = false,
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        loadExecutionProfile()
        viewModelScope.launch(Dispatchers.IO) {
            val settings = repository.debugSettings()
            mutableState.update {
                it.copy(
                    debugExportEnabled = settings.exportEnabled,
                    debugExportLocation = settings.exportLocation,
                    debugKernelLogEnabled = settings.kernelLogEnabled,
                )
            }
        }
    }

    fun onCloseAdvanced() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = false,
                aboutVisible = false,
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
    }

    fun onOpenParameters() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = true,
                parametersVisible = true,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        loadExecutionProfile()
    }

    fun onCloseParameters() {
        mutableState.update {
            it.copy(
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
    }

    /** Opens the configuration-loading screen and refreshes the stored list. */
    fun onOpenLoadConfig() {
        mutableState.update {
            it.copy(
                loadConfigVisible = true,
                builtinScreenVisible = false,
                userProfileDetail = null,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        viewModelScope.launch(Dispatchers.IO) { refreshUserProfiles() }
    }

    fun onCloseLoadConfig() {
        mutableState.update {
            it.copy(loadConfigVisible = false, builtinScreenVisible = false, userProfileDetail = null)
        }
    }

    fun onOpenUserProfileDetail(name: String) {
        mutableState.update { it.copy(userProfileDetail = name, builtinScreenVisible = false) }
    }

    fun onCloseUserProfileDetail() {
        mutableState.update { it.copy(userProfileDetail = null) }
    }

    /** Loads a stored document into the imported layer. */
    fun onLoadUserProfile(name: String) = selectUserProfile(name)

    /** Unloads the imported layer, back to built-in plus overrides. */
    fun onUnloadUserProfile() = selectUserProfile(null)

    /**
     * Loads the document and opens the shared parameter-override editor, so
     * "modify" reuses the exact same UI as the parameter overrides.
     */

    private fun selectUserProfile(name: String?) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching {
                profileController.selectUserProfile(name, snapshot.kernelRelease, pair)
            }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.user_profile_load_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            refreshSnapshot()
            send(
                GhostlockEffect.Toast(
                    if (name != null) R.string.user_profile_loaded
                    else R.string.user_profile_unloaded,
                ),
            )
        }
    }

    private suspend fun refreshUserProfiles() {
        val profiles = runCatching { repository.userProfiles() }.getOrDefault(emptyList())
        mutableState.update { it.copy(userProfiles = profiles) }
    }

    /** Renames a stored document through the shared text-input dialog. */
    fun onUserProfileRename(name: String) {
        mutableState.update {
            it.copy(
                userProfileRenameTarget = name,
                dialogVisible = true,
                dialogType = DialogType.INPUT,
                dialogTitleRes = R.string.user_profile_rename,
                dialogMessageRes = R.string.user_profile_rename_hint,
                dialogInput = name,
                dialogConfirmLabelRes = R.string.user_profile_rename_confirm,
            )
        }
    }

    private fun renameUserProfile(name: String, newName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val renamed = runCatching { repository.renameUserProfile(name, newName) }.getOrNull()
            refreshUserProfiles()
            if (renamed != null) {
                mutableState.update { state ->
                    state.copy(
                        activeUserProfile = if (state.activeUserProfile == name) {
                            renamed
                        } else {
                            state.activeUserProfile
                        },
                        userProfileDetail = if (state.userProfileDetail == name) {
                            renamed
                        } else {
                            state.userProfileDetail
                        },
                    )
                }
            }
            send(
                GhostlockEffect.Toast(
                    if (renamed != null) R.string.user_profile_renamed
                    else R.string.user_profile_rename_failed,
                ),
            )
        }
    }

    /** Renders the stored document as HOCON and shares it. */
    fun onUserProfileExport(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { repository.exportUserProfile(name) }
                .onSuccess { uri -> send(GhostlockEffect.Share(uri)) }
                .onFailure {
                    android.util.Log.e("GhostLock", "export user profile failed", it)
                    send(GhostlockEffect.Toast(R.string.export_failed))
                }
        }
    }

    /** Converts a legacy document into a current-layout copy in the store. */
    fun onConvertUserProfile(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val converted = runCatching { repository.convertUserProfile(name) }.getOrNull()
            refreshUserProfiles()
            send(
                GhostlockEffect.Toast(
                    if (converted != null) R.string.user_profile_converted
                    else R.string.user_profile_convert_failed,
                ),
            )
        }
    }

    fun onUserProfileDelete(name: String) {
        mutableState.update { it.copy(userProfileDeleteTarget = name) }
    }

    fun onUserProfileDeleteConfirm() {
        val name = state.value.userProfileDeleteTarget ?: return
        mutableState.update { it.copy(userProfileDeleteTarget = null) }
        viewModelScope.launch(Dispatchers.IO) {
            val ok = runCatching { repository.deleteUserProfile(name) }.getOrDefault(false)
            refreshUserProfiles()
            if (ok) {
                mutableState.update { current ->
                    current.copy(
                        activeUserProfile = current.activeUserProfile?.takeIf { it != name },
                        userProfileDetail = current.userProfileDetail?.takeIf { it != name },
                    )
                }
                refreshSnapshot()
            }
            send(
                GhostlockEffect.Toast(
                    if (ok) R.string.user_profile_deleted else R.string.user_profile_delete_failed,
                ),
            )
        }
    }

    fun onUserProfileDeleteDismiss() {
        mutableState.update { it.copy(userProfileDeleteTarget = null) }
    }

    fun onShowAbout() {
        mutableState.update { it.copy(aboutVisible = true) }
    }

    fun onCloseAbout() {
        mutableState.update { it.copy(aboutVisible = false) }
    }

    fun onDebugExportChanged(enabled: Boolean) {
        repository.setDebugExportEnabled(enabled)
        mutableState.update { it.copy(debugExportEnabled = enabled) }
    }

    fun onDebugExportLocationPick() = send(GhostlockEffect.PickDebugFolder)

    fun onDebugExportLocationPicked(location: String?) {
        if (location.isNullOrBlank()) {
            send(GhostlockEffect.Toast(R.string.debug_export_location_unsupported))
            return
        }
        repository.setDebugExportLocation(location)
        mutableState.update { it.copy(debugExportLocation = location) }
    }

    fun onDebugKernelLogChanged(enabled: Boolean) {
        repository.setDebugKernelLogEnabled(enabled)
        mutableState.update { it.copy(debugKernelLogEnabled = enabled) }
    }

    /** Saves the merged profile through the system document dialog. */
    fun onExportProfile() {
        val release = kernelSnapshot?.kernelRelease ?: return
        send(GhostlockEffect.CreateProfileDocument(exportDocumentName(release)))
    }

    fun onExportProfileDocumentPicked(documentUri: String?) {
        if (documentUri.isNullOrBlank()) return
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val ok = profileController.export(snapshot.kernelRelease, pair, documentUri)
            send(
                GhostlockEffect.Toast(
                    if (ok) R.string.override_export_done else R.string.export_failed,
                ),
            )
        }
    }

    private fun exportDocumentName(release: String): String =
        "${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}.conf"

    /* ---- editing session: draft edits plus an isolated controller ---- */

    private fun currentPair(): CpuPair? {
        val snapshot = kernelSnapshot ?: return null
        return snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair)
    }

    /** Opens the editor for the profile the attack controller currently loads. */
    fun onOpenProfileOverrides() {
        openEditSession(profileController.activeUserProfile(), fromDetail = false)
    }

    /**
     * Opens the editor for the stored document [name] without loading it into
     * the attack controller: a private session controller resolves the edits.
     */
    fun onEditUserProfile(name: String) {
        val profile = state.value.userProfiles.firstOrNull { it.name == name }
        if (profile?.version == 1) {
            send(GhostlockEffect.Toast(R.string.user_profile_legacy_hint))
            return
        }
        openEditSession(name, fromDetail = true)
    }

    private fun openEditSession(name: String?, fromDetail: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching { repository.beginEditSession(name) }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.user_profile_load_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            mutableState.update {
                it.copy(
                    builtinScreenVisible = false,
                    advancedOverrideVisible = false,
                    profileOverrideVisible = true,
                    editTargetName = name,
                    userProfileDetail = if (fromDetail) it.userProfileDetail else null,
                    loadConfigVisible = if (fromDetail) it.loadConfigVisible else false,
                )
            }
        }
    }

    /** Reloads the session, dropping every unsaved edit. */
    fun onRevertProfileEdits() {
        loadEditSession()
        send(GhostlockEffect.Toast(R.string.profile_reverted))
    }

    private fun loadEditSession(preserveEditing: Boolean = false) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        val session = repository.editSessionController() ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val release = repository.editSessionRelease() ?: snapshot.kernelRelease
            val config = runCatching { session.load(release, pair) }.getOrNull()
                ?: return@launch
            applyExecutionConfig(config, preserveEditing)
            applyAdvancedConfig(config, preserveEditing)
        }
    }

    /** Writes the draft (general, route/fallback, advanced) into the session. */
    private suspend fun commitDraftToSession(): ProfileConfig? {
        val snapshot = kernelSnapshot ?: return null
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return null
        val session = repository.editSessionController() ?: return null
        val release = repository.editSessionRelease() ?: snapshot.kernelRelease
        val general = mutableState.value.executionEditing.mapNotNull { (path, text) ->
            text.trim().toLongOrNull()?.let { value -> path to value }
        }.toMap()
        session.updateGeneral(release, pair, general)
        session.updateRoute(release, pair, mutableState.value.profileRoute)
        session.updateFallback(release, pair, mutableState.value.profileFallback)
        /* General edits share the execution.* tree paths. The advanced rebuild
         * replaces the whole override entry, so the drafts must be merged in or
         * the general edits would be dropped. */
        val drafts = mutableState.value.profileOverrideEditing +
                mutableState.value.executionEditing
        val advanced = drafts.mapNotNull { (path, text) ->
            text.trim().toLongOrNull()?.let { value -> path to value }
        }.toMap()
        return runCatching { session.updateAdvanced(release, pair, advanced) }.getOrNull()
    }

    /**
     * Commits the draft: a loaded profile gets the overrides written back to
     * the live controller, an unloaded one is stored as a new profile.
     */
    fun onSaveProfileEdits() {
        val pair = currentPair() ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val config = commitDraftToSession()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.execution_save_failed))
                return@launch
            }
            if (repository.editSessionIsLive()) {
                val committed = runCatching { repository.commitEditSession() }
                    .getOrDefault(false)
                if (!committed) {
                    send(GhostlockEffect.Toast(R.string.execution_save_failed))
                    return@launch
                }
                val live = runCatching { profileController.load(config.release, pair) }.getOrNull()
                if (live != null) {
                    applyExecutionConfig(live, preserveEditing = false)
                    applyAdvancedConfig(live, preserveEditing = false)
                }
                send(GhostlockEffect.Toast(R.string.profile_saved))
            } else if (repository.editSessionTarget() != null) {
                /* Editing a stored document that is not loaded: Save updates
                 * that document in place, Save as creates a copy. */
                val saved = runCatching { repository.saveEditSessionInPlace() }
                    .getOrDefault(false)
                refreshUserProfiles()
                send(
                    GhostlockEffect.Toast(
                        if (saved) R.string.profile_saved else R.string.execution_save_failed,
                    ),
                )
            } else {
                val name = repository.saveEditSessionAsNew()
                refreshUserProfiles()
                send(
                    GhostlockEffect.Toast(
                        if (name != null) R.string.profile_saved_as_new
                        else R.string.execution_save_failed,
                    ),
                )
            }
        }
    }

    /** Stores the session result as a new saved profile. */
    fun onSaveProfileAs() {
        viewModelScope.launch(Dispatchers.IO) {
            if (commitDraftToSession() == null) {
                send(GhostlockEffect.Toast(R.string.execution_save_failed))
                return@launch
            }
            val name = repository.saveEditSessionAsNew()
            refreshUserProfiles()
            send(
                GhostlockEffect.Toast(
                    if (name != null) R.string.profile_saved_as_new
                    else R.string.execution_save_failed,
                ),
            )
        }
    }

    /** Renders the session result as HOCON and shares it. */
    fun onExportProfileEdits() {
        viewModelScope.launch(Dispatchers.IO) {
            if (commitDraftToSession() == null) {
                send(GhostlockEffect.Toast(R.string.export_failed))
                return@launch
            }
            runCatching { repository.exportEditSession() }
                .onSuccess { uri -> send(GhostlockEffect.Share(uri)) }
                .onFailure { send(GhostlockEffect.Toast(R.string.export_failed)) }
        }
    }

    /** Opens the builtin picker; overrides stay keyed to the device kernel. */
    fun onOpenBuiltinProfiles() {
        val snapshot = kernelSnapshot ?: return
        mutableState.update { it.copy(builtinScreenVisible = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val releases = runCatching { profileController.builtinReleases() }
                .getOrDefault(emptyList())
            val templates = releases.filter {
                it.endsWith(ProfileConfigController.TemplateSuffix)
            }
            val kernels = releases.filterNot {
                it.endsWith(ProfileConfigController.TemplateSuffix)
            }
            if (templates.isEmpty() && kernels.isEmpty()) {
                send(GhostlockEffect.Toast(R.string.load_builtin_failed))
                return@launch
            }
            mutableState.update {
                it.copy(
                    builtinTemplates = sortByKernelSimilarity(
                        snapshot.kernelRelease, templates,
                    ),
                    builtinProfiles = sortByKernelSimilarity(
                        snapshot.kernelRelease, kernels,
                    ),
                )
            }
        }
    }

    fun onCloseBuiltinProfiles() {
        mutableState.update { it.copy(builtinScreenVisible = false) }
    }

    fun onSelectBuiltinProfile(release: String?) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            /* The controller keeps a single active source: picking a builtin
             * unloads whatever user document was loaded before. */
            val config = runCatching {
                profileController.selectUserProfile(null, snapshot.kernelRelease, pair)
                profileController.selectBuiltin(release, snapshot.kernelRelease, pair)
            }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.load_builtin_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            refreshSnapshot()
            send(GhostlockEffect.Toast(R.string.load_builtin_done))
        }
    }

    /** Orders releases by absolute major/minor/fix/android distance to device. */
    private fun sortByKernelSimilarity(deviceRelease: String, releases: List<String>): List<String> {
        val device = kernelVersionKey(deviceRelease)
        return releases.sortedWith(Comparator { a, b ->
            compareIntLists(
                similarityKey(device, kernelVersionKey(a)),
                similarityKey(device, kernelVersionKey(b)),
            )
        })
    }

    private fun kernelVersionKey(release: String): List<Int> {
        val version = release.substringBefore('-').split('.')
            .mapNotNull { it.toIntOrNull() }
        val android = Regex("-android(\\d+)").find(release)
            ?.groupValues?.get(1)?.toIntOrNull()
        return if (android == null) version else version + android
    }

    private fun similarityKey(device: List<Int>, candidate: List<Int>): List<Int> =
        (0 until maxOf(device.size, candidate.size)).map { index ->
            kotlin.math.abs((device.getOrNull(index) ?: 0) - (candidate.getOrNull(index) ?: 0))
        }

    private fun compareIntLists(a: List<Int>, b: List<Int>): Int {
        for (index in 0 until maxOf(a.size, b.size)) {
            val result = (a.getOrNull(index) ?: 0).compareTo(b.getOrNull(index) ?: 0)
            if (result != 0) return result
        }
        return 0
    }

    fun onCloseProfileOverrides() {
        repository.endEditSession()
        mutableState.update {
            it.copy(
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
                editTargetName = null,
            )
        }
    }

    fun onOpenAdvancedOverrides() {
        mutableState.update { it.copy(advancedOverrideVisible = true) }
        loadEditSession()
    }

    fun onCloseAdvancedOverrides() {
        mutableState.update { it.copy(advancedOverrideVisible = false) }
    }

    /** Advanced edits are draft-only; saving the session commits them. */
    fun onProfileOverrideChanged(path: String, value: String) {
        mutableState.update {
            it.copy(
                profileOverrideEditing = it.profileOverrideEditing + (path to value),
            )
        }
    }

    private fun applyAdvancedConfig(config: ProfileConfig, preserveEditing: Boolean) {
        mutableState.update { state ->
            state.copy(
                profileOverrideRelease = config.release,
                profileOverrideRoots = config.roots,
                profileOverrideEditing = if (preserveEditing) state.profileOverrideEditing
                else flattenLeaves(config.roots).associate { field ->
                    field.path to (field.value?.toString() ?: "")
                },
                profileInvalidPaths = config.invalidPaths,
                profileRoute = config.route,
                profileFallback = config.fallbackTo,
                activeBuiltinProfile = profileController.activeBuiltinRelease(),
                activeUserProfile = profileController.activeUserProfile(),
            )
        }
    }

    private fun flattenLeaves(nodes: List<ProfileFieldNode>): List<ProfileFieldNode> =
        nodes.flatMap { node -> if (node.isGroup) flattenLeaves(node.children) else listOf(node) }

    fun selectCpuPair(index: Int) {
        val snapshot = kernelSnapshot ?: return
        if (index !in snapshot.cpuPairs.indices) return
        selectCpuPairUseCase(index)
        kernelSnapshot = snapshot.copy(selectedCpuPair = index)
        mutableState.update { it.copy(cpuPairIndex = index) }
        /* Picking a preset pair replaces an explicit profile selection. */
        if (mutableState.value.customCpuPair != null) {
            viewModelScope.launch(Dispatchers.IO) {
                val config = runCatching {
                    profileController.clearSelectedCpus(
                        snapshot.kernelRelease,
                        snapshot.cpuPairs[index],
                    )
                }.getOrNull() ?: return@launch
                applyExecutionConfig(config, preserveEditing = false)
                applyAdvancedConfig(config, preserveEditing = false)
            }
        }
    }

    fun toggleSafeMode(enabled: Boolean) {
        repository.setSafeModeEnabled(enabled)
        mutableState.update { it.copy(safeModeEnabled = enabled) }
    }

    fun toggleForceAttackTest(enabled: Boolean) {
        repository.setForceAttackTest(enabled)
        mutableState.update { it.copy(forceAttackTestEnabled = enabled) }
    }

    fun toggleShizuku(enabled: Boolean) {
        repository.setShizukuEnabled(enabled)
        mutableState.update { it.copy(shizukuEnabled = enabled) }
        if (!enabled && kernelSnapshot?.recommendShizuku == true) {
            send(GhostlockEffect.Toast(R.string.shizuku_recommended_hint))
        }
        // The grant dialog lands in another app, so the status is re-read and
        // onResume() refreshes it again when the dialog closes.
        viewModelScope.launch { refreshSnapshot() }
    }

    fun onOpenManagerPicker() {
        mutableState.update { it.copy(managerPickerVisible = true) }
        viewModelScope.launch {
            val candidates = repository.installedManagers()
            mutableState.update {
                it.copy(
                    managerCandidates = candidates,
                    selectedManagerPackage = repository.selectedManagerPackage(),
                )
            }
        }
    }

    fun onCloseManagerPicker() {
        mutableState.update { it.copy(managerPickerVisible = false) }
    }

    fun onManagerSelected(pkg: String?) {
        repository.setSelectedManagerPackage(pkg)
        mutableState.update { it.copy(selectedManagerPackage = pkg, managerPickerVisible = false) }
    }

    fun onRun() = runExploit()

    /* ---- exploit chain (Ghostlock / TimerRoot) ---- */

    fun onExploitChainSelected(index: Int) {
        val chain = if (index == 1) ExploitChain.TIMER_ROOT else ExploitChain.GHOSTLOCK
        repository.setExploitChain(chain)
        mutableState.update { it.copy(exploitChain = chain) }
        viewModelScope.launch(Dispatchers.IO) { refreshTimerRootState() }
    }

    fun onOpenKsudLibraryPicker() {
        viewModelScope.launch(Dispatchers.IO) {
            val entries = runCatching { repository.listKsudLibraries() }.getOrDefault(emptyList())
            val chosen = repository.ksudLibraryChoice()
            mutableState.update {
                it.copy(
                    ksudEntries = entries,
                    ksudPickerVisible = entries.isNotEmpty(),
                    ksudSelectedEntry = chosen,
                )
            }
            if (entries.isEmpty()) {
                send(GhostlockEffect.Toast(R.string.ksud_picker_empty))
            }
        }
    }

    fun onCloseKsudLibraryPicker() {
        mutableState.update { it.copy(ksudPickerVisible = false) }
    }

    fun onKsudLibrarySelected(entry: String?) {
        repository.setKsudLibraryChoice(entry)
        mutableState.update {
            it.copy(ksudSelectedEntry = entry, ksudPickerVisible = false)
        }
    }

    fun onImportTimerRootBinary(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { repository.importTimerRootBinary(uri) }
                .onSuccess {
                    appendLog("t98260 imported")
                    refreshTimerRootState()
                    send(GhostlockEffect.Toast(R.string.timerroot_binary_imported))
                }
                .onFailure {
                    appendLog("t98260 import failed: ${it.message}")
                    send(GhostlockEffect.Toast(R.string.timerroot_binary_invalid))
                }
        }
    }

    fun onImportTimerRootSyms(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { repository.importTimerRootSyms(uri) }
                .onSuccess {
                    appendLog("ic-syms table imported")
                    refreshTimerRootState()
                }
                .onFailure {
                    appendLog("ic-syms import failed: ${it.message}")
                    send(GhostlockEffect.Toast(R.string.timerroot_syms_invalid))
                }
        }
    }

    fun onParseTimerRootSyms(input: String) {
        onParseTimerRootSymsInternal(input)
    }

    /** 98260 配置: parse a picked local image (full OTA zip / boot.img /
     * payload.bin) into the staged table. The extractor sniffs the container
     * itself, so one funnel covers all three. */
    private fun parseTimerRootInput(uri: String, cacheName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val staged = runCatching { readDocumentUseCase.cache(uri, cacheName) }
                .onFailure {
                    appendLog("98260 parse error: ${it.message}")
                    send(GhostlockEffect.Toast(R.string.timerroot_parse_failed))
                }
                .getOrNull()
                ?: return@launch
            appendLog("98260 source staged: $staged")
            onParseTimerRootSymsInternal(staged)
        }
    }

    /** Shared by the URL dialog action and the picked-file funnel. */
    private fun onParseTimerRootSymsInternal(input: String) {
        if (!beginOperation()) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                when (val result = repository.parseTimerRootSyms(input, ::appendLog)) {
                    is ParseResult.Parsed -> {
                        appendLog("ic-syms: table staged for ${result.releases.firstOrNull() ?: "?"}")
                        refreshTimerRootState()
                    }
                    is ParseResult.Failed ->
                        appendLog("ic-syms: parse failed (${result.reason ?: "exit ${result.code}"})")
                    else -> {}
                }
            } finally {
                endOperation()
            }
        }
    }

    /** Shares the staged table (98260 配置) as a Download/ file. */
    fun onExportTimerRootSyms() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { repository.publishTimerRootSyms() }
                .onSuccess { uri ->
                    appendLog("ic-syms: table exported")
                    send(GhostlockEffect.Share(uri))
                }
                .onFailure {
                    appendLog("ic-syms: export failed: ${it.message}")
                    send(GhostlockEffect.Toast(R.string.timerroot_syms_missing))
                }
        }
    }

    /** Drops the imported binary; the run falls back to the bundled
     * libtimerroot.so. */
    fun onRemoveTimerRootBinary() {
        viewModelScope.launch(Dispatchers.IO) {
            repository.removeTimerRootBinary()
            appendLog("t98260 import removed; falling back to the bundled library")
            refreshTimerRootState()
        }
    }

    private suspend fun refreshTimerRootState() {
        runCatching { repository.timerRootState() }.onSuccess { state ->
            mutableState.update {
                it.copy(
                    timerRootBinaryAvailable = state.binaryAvailable,
                    timerRootBinarySource = state.binarySource,
                    timerRootBinarySize = state.binarySizeBytes,
                    timerRootSymsRelease = state.symsRelease,
                    timerRootSymsSymbols = state.symsSymbols,
                    timerRootSymsGeometryKeys = state.symsGeometryKeys,
                    timerRootSymsGeometryEssential = state.symsGeometryEssential,
                    ksudSelectedEntry = state.ksudEntry,
                    timerRootAllowAnyKernel = state.allowAnyKernel,
                )
            }
        }
    }

    /** IC_ALLOW_ANY_KERNEL gate for the TimerRoot chain; persisted, and the
     * config sheet reflects it through refreshTimerRootState(). */
    fun toggleTimerRootAllowAnyKernel(enabled: Boolean) {
        repository.setTimerRootAllowAnyKernel(enabled)
        mutableState.update { it.copy(timerRootAllowAnyKernel = enabled) }
    }

    /** Post-escalation convenience: auto-open the root manager when a chain
     * finishes successfully. Both chains consult the same preference. */
    fun toggleLaunchManagerOnSuccess(enabled: Boolean) {
        repository.setLaunchManagerOnSuccess(enabled)
        mutableState.update { it.copy(launchManagerOnSuccess = enabled) }
    }

    /** Best-effort follow-up after a successful run: launch the selected (or
     * auto-resolved) root manager so the user lands on the manager screen
     * instead of the log. Failures are logged, never fatal. */
    private fun maybeLaunchRootManager() {
        if (!repository.launchManagerOnSuccess()) return
        viewModelScope.launch(Dispatchers.Main) {
            val pkg = runCatching { repository.launchRootManager() }.getOrNull()
            if (pkg != null) {
                appendLog("[+] launched root manager: $pkg")
            } else {
                appendLog("[!] could not launch a root manager (none installed or blocked)")
            }
        }
    }

    /** Explains why the run button is greyed out. */
    fun onProfileInvalid() {
        val state = state.value
        val messageRes = when {
            !state.executionHasProfile -> R.string.run_blocked_no_profile
            state.shizukuEnabled && state.shizukuStatus != ShizukuStatus.READY ->
                R.string.run_blocked_shizuku

            else -> R.string.profile_invalid
        }
        send(GhostlockEffect.Toast(messageRes))
    }

    fun onStatusClick() {
        val snapshot = kernelSnapshot ?: return
        /* shizukuEnabled already carries the profile suggestion unless the
         * user overrode it (PROFILE-SUGGEST-01). */
        if (!snapshot.shizukuEnabled) return
        when (snapshot.shizukuStatus) {
            ShizukuStatus.NOT_RUNNING -> send(GhostlockEffect.OpenShizuku)
            ShizukuStatus.PERMISSION_REQUIRED -> repository.requestShizukuPermission()
            ShizukuStatus.NOT_REQUIRED,
            ShizukuStatus.READY,
                -> Unit
        }
    }

    private fun runExploit() {
        val snapshot = kernelSnapshot ?: return
        if (repository.exploitChain() == ExploitChain.TIMER_ROOT) {
            runTimerRoot()
            return
        }
        if (!snapshot.kernelSupported) {
            if (beginOperation()) {
                appendLog("result: exploit chain unsupported by this kernel")
                endOperation()
            }
            return
        }
        val useShizuku = snapshot.shizukuEnabled
        if (useShizuku && snapshot.shizukuStatus != ShizukuStatus.READY) {
            onStatusClick()
            return
        }
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        if (!beginOperation()) return
        send(GhostlockEffect.KeepScreenAwake(true))
        appendLog("==== start ${if (useShizuku) "Shizuku/V20" else "base"} ====")
        appendLog("cpu pair: ${snapshot.cpuPairLabels.getOrElse(snapshot.selectedCpuPair) { pair.toString() }}")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val code = runExploitUseCase(pair, useShizuku, ::appendLog)
                appendLog(if (code == 0) "result: exploit completed" else "result: exploit failed (exit code=$code)")
                appendLog("exit code=$code")
                if (code == 0) maybeLaunchRootManager()
            } finally {
                endOperation()
                send(GhostlockEffect.KeepScreenAwake(false))
            }
        }
    }

    /** TimerRoot chain: always Shizuku (98260 reads tracefs, shell domain only). */
    private fun runTimerRoot() {
        val state = state.value
        if (!state.timerRootBinaryAvailable) {
            send(GhostlockEffect.Toast(R.string.timerroot_binary_missing))
            onOpenTimerRootConfig()
            return
        }
        /* Pre-flight the Shizuku gate the same way the GhostLock chain does:
 * guide the user to start it (or grant) instead of failing inside the
 * runner with a log-only error. */
        val shizukuStatus = kernelSnapshot?.shizukuStatus ?: ShizukuStatus.NOT_RUNNING
        if (shizukuStatus != ShizukuStatus.READY) {
            when (shizukuStatus) {
                ShizukuStatus.NOT_RUNNING -> {
                    send(GhostlockEffect.Toast(R.string.timerroot_needs_shizuku))
                    send(GhostlockEffect.OpenShizuku)
                }
                ShizukuStatus.PERMISSION_REQUIRED -> repository.requestShizukuPermission()
                ShizukuStatus.NOT_REQUIRED, ShizukuStatus.READY -> Unit
            }
            return
        }
        if (!beginOperation()) return
        send(GhostlockEffect.KeepScreenAwake(true))
        appendLog("==== start TimerRoot (CVE-2026-98260) ====")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val logTail = StringBuilder()
                val code = repository.runExploitAsTimerRoot { line ->
                    logTail.append(line).append('\n')
                    appendLog(line)
                }
                appendLog(if (code == 0) "result: chain completed" else "result: chain failed (exit code=$code)")
                appendLog("exit code=$code")
                if (code == 0) {
                    maybeLaunchRootManager()
                } else if (logTail.contains("does not match profile")) {
                    /* t98260 refused to run: its built-in kernel profile does
                     * not cover this device. The two ways out are a matching
                     * t98260 build, or the explicit IC_ALLOW_ANY_KERNEL
                     * override with a staged ic-syms table. */
                    appendLog(
                        "<t> hint: this t98260 was built for a different kernel; " +
                            "either import a matching build, or stage a symbol table and enable " +
                            "IC_ALLOW_ANY_KERNEL in the TimerRoot config",
                    )
                    onOpenTimerRootConfig()
                }
            } finally {
                endOperation()
                send(GhostlockEffect.KeepScreenAwake(false))
            }
        }
    }

    fun onOpenTimerRootConfig() {
        mutableState.update {
            it.copy(
                timerRootConfigVisible = true,
                timerRootLoadConfigVisible = false,
                timerRootEditVisible = false,
                timerRootDocsVisible = false,
            )
        }
        viewModelScope.launch(Dispatchers.IO) { refreshTimerRootState() }
    }

    fun onCloseTimerRootConfig() {
        mutableState.update {
            it.copy(
                timerRootConfigVisible = false,
                timerRootLoadConfigVisible = false,
                timerRootEditVisible = false,
                timerRootDocsVisible = false,
            )
        }
    }

    /* ---- TimerRoot 配置的多级页 ---- */

    fun onOpenTimerRootLoadConfig() {
        mutableState.update { it.copy(timerRootLoadConfigVisible = true) }
        viewModelScope.launch(Dispatchers.IO) { refreshTimerRootState() }
    }

    fun onCloseTimerRootLoadConfig() {
        mutableState.update { it.copy(timerRootLoadConfigVisible = false) }
    }

    fun onOpenTimerRootDocs() {
        mutableState.update { it.copy(timerRootDocsVisible = true) }
    }

    fun onCloseTimerRootDocs() {
        mutableState.update { it.copy(timerRootDocsVisible = false) }
    }

    /**
     * Loads the staged ic-syms table into the edit fields. Only the `off.*`
     * geometry block and the hard target symbol are editable — the rest of the
     * table is preserved verbatim on save.
     */
    fun onOpenTimerRootEdit() {
        viewModelScope.launch(Dispatchers.IO) {
            val text = runCatching { repository.readTimerRootSyms() }.getOrNull()
            if (text == null) {
                send(GhostlockEffect.Toast(R.string.timerroot_edit_no_table))
                return@launch
            }
            val fields = timerRootEditFieldsOf(text)
            mutableState.update {
                it.copy(
                    timerRootEditVisible = true,
                    timerRootEditFields = fields,
                    timerRootEditDirty = false,
                )
            }
        }
    }

    fun onCloseTimerRootEdit() {
        mutableState.update { it.copy(timerRootEditVisible = false) }
    }

    fun onTimerRootFieldChanged(index: Int, value: String) {
        mutableState.update { current ->
            val fields = current.timerRootEditFields.toMutableList()
            if (index in fields.indices) {
                fields[index] = fields[index].copy(value = value)
            }
            current.copy(timerRootEditFields = fields, timerRootEditDirty = true)
        }
    }

    /** Saves the edited fields back into the staged table. */
    fun onSaveTimerRootEdits() {
        viewModelScope.launch(Dispatchers.IO) {
            val text = runCatching { repository.readTimerRootSyms() }.getOrNull()
            if (text == null) {
                send(GhostlockEffect.Toast(R.string.timerroot_edit_no_table))
                return@launch
            }
            val edited = applyTimerRootEdits(text, state.value.timerRootEditFields)
            /* Gate the write on the hard target: a table whose
             * __tracepoint_sys_exit no longer parses is refused, not saved. */
            val summary = TimerRootTable.summarize(edited)
            if (!summary.hasTracepointTarget) {
                appendLog("timerroot edit rejected: no __tracepoint_sys_exit value")
                send(GhostlockEffect.Toast(R.string.timerroot_edit_invalid))
                return@launch
            }
            val ok = repository.writeTimerRootSyms(edited)
            if (ok) {
                appendLog("ic-syms table edited (${state.value.timerRootEditFields.size} fields)")
                refreshTimerRootState()
                mutableState.update { it.copy(timerRootEditDirty = false) }
                send(GhostlockEffect.Toast(R.string.timerroot_edit_saved))
            } else {
                send(GhostlockEffect.Toast(R.string.timerroot_edit_invalid))
            }
        }
    }

    /** Reloads the edit fields from the staged table, discarding changes. */
    fun onRevertTimerRootEdits() {
        viewModelScope.launch(Dispatchers.IO) {
            val text = runCatching { repository.readTimerRootSyms() }.getOrNull()
            if (text == null) {
                send(GhostlockEffect.Toast(R.string.timerroot_edit_no_table))
                return@launch
            }
            mutableState.update {
                it.copy(
                    timerRootEditFields = timerRootEditFieldsOf(text),
                    timerRootEditDirty = false,
                )
            }
        }
    }

    fun onCloseExecutionSheet() {
        if (running && !state.value.executionSheetDismissible) return
        mutableState.update { it.copy(executionSheetVisible = false) }
    }

    fun copyLogs() {
        val text = state.value.logLines.joinToString(separator = "") { it.text }
        send(GhostlockEffect.Clipboard(text))
        send(GhostlockEffect.Toast(R.string.copied))
    }

    fun importOffsetsHocon() =
        send(GhostlockEffect.PickDocument(DocumentRequest.ImportOffsetsHocon))

    fun importOffsetsJson() =
        send(GhostlockEffect.PickDocument(DocumentRequest.ImportOffsetsJson))

    fun onPickTimerRootBinary() =
        send(GhostlockEffect.PickDocument(DocumentRequest.TimerRootBinary))

    fun onPickTimerRootSyms() =
        send(GhostlockEffect.PickDocument(DocumentRequest.TimerRootSyms))

    fun onPickTimerRootOta() =
        send(GhostlockEffect.PickDocument(DocumentRequest.TimerRootOtaZip))

    fun onPickTimerRootImage() =
        send(GhostlockEffect.PickDocument(DocumentRequest.TimerRootImage))

    fun parseOffsets() {
        parseDialogStage = ParseDialogStage.Mode
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.LIST,
                dialogTitleRes = R.string.parse_title,
                dialogItems = emptyList(),
                dialogItemResIds = listOf(
                    R.string.parse_option_payload,
                    R.string.parse_option_boot,
                ),
            )
        }
    }

    /** Attachment step: shown once a source is staged and re-shown after every
     * extra image, so any combination is reachable without one entry per
     * combination. vendor_boot.img belongs here: on MediaTek it supplies
     * kernel_phys_load, and on vivo/iQOO it carries the vr.ko module the
     * runtime probe reads. */
    private fun promptAttach() {
        parseDialogStage = ParseDialogStage.Attach
        val options = buildList {
            add(AttachOption.START to R.string.parse_attach_start)
            add(AttachOption.XBL to R.string.parse_attach_xbl)
            add(AttachOption.UEFI to R.string.parse_attach_uefi)
            /* Already staged: say so, so "nothing happened" cannot be the
             * user's only signal that the import worked. */
            add(
                AttachOption.VENDOR_BOOT to if (vendorBootImported || stagedVendorBoot() != null) {
                    R.string.parse_attach_vendor_boot_staged
                } else {
                    R.string.parse_attach_vendor_boot
                },
            )
        }
        pendingAttachOptions = options.map { it.first }
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.LIST,
                dialogTitleRes = R.string.parse_boot_attach_title,
                dialogItems = emptyList(),
                dialogItemResIds = options.map { it.second },
            )
        }
    }

    fun promptParseUrl() {
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.INPUT,
                dialogTitleRes = R.string.parse_url_title,
                dialogMessageRes = R.string.parse_url_hint,
                dialogInput = "",
                dialogConfirmLabelRes = R.string.parse_start,
            )
        }
    }

    fun onDocumentResult(request: DocumentRequest, uri: String) {
        when (request) {
            DocumentRequest.BootImage -> stageBoot(uri)
            DocumentRequest.XblImage -> stageXbl(uri)
            DocumentRequest.UefiImage -> stageUefi(uri)
            DocumentRequest.VendorBootImage -> stageVendorBoot(uri)
            DocumentRequest.PayloadImage -> stagePayload(uri)
            DocumentRequest.TimerRootBinary -> onImportTimerRootBinary(uri)
            DocumentRequest.TimerRootSyms -> onImportTimerRootSyms(uri)
            DocumentRequest.TimerRootOtaZip -> parseTimerRootInput(uri, "ota.zip")
            DocumentRequest.TimerRootImage -> parseTimerRootInput(uri, "image.bin")
            DocumentRequest.ImportOffsetsHocon, DocumentRequest.ImportOffsetsJson -> Unit
        }
    }

    /** Multi-picked documents (a profile plus any include dependencies). */
    fun onDocumentsResult(request: DocumentRequest, uris: List<String>) {
        when (request) {
            DocumentRequest.ImportOffsetsHocon, DocumentRequest.ImportOffsetsJson ->
                importDocuments(uris)

            DocumentRequest.BootImage -> uris.firstOrNull()?.let(::stageBoot)
            DocumentRequest.XblImage -> uris.firstOrNull()?.let(::stageXbl)
            DocumentRequest.UefiImage -> uris.firstOrNull()?.let(::stageUefi)
            DocumentRequest.VendorBootImage -> uris.firstOrNull()?.let(::stageVendorBoot)
            DocumentRequest.PayloadImage -> uris.firstOrNull()?.let(::stagePayload)
            DocumentRequest.TimerRootBinary -> uris.firstOrNull()?.let(::onImportTimerRootBinary)
            DocumentRequest.TimerRootSyms -> uris.firstOrNull()?.let(::onImportTimerRootSyms)
            DocumentRequest.TimerRootOtaZip -> uris.firstOrNull()?.let { parseTimerRootInput(it, "ota.zip") }
            DocumentRequest.TimerRootImage -> uris.firstOrNull()?.let { parseTimerRootInput(it, "image.bin") }
        }
    }

    fun onDialogItemSelected(index: Int) {
        dismissDialog()
        when (parseDialogStage) {
            ParseDialogStage.Mode -> when (index) {
                0 -> pickPayload()
                1 -> pickBoot()
            }

            ParseDialogStage.Attach -> when (pendingAttachOptions.getOrNull(index)) {
                /* Start, or attach one more image and come straight back here. */
                AttachOption.START -> startPendingParse()
                AttachOption.XBL -> send(GhostlockEffect.PickDocument(DocumentRequest.XblImage))
                AttachOption.UEFI -> send(GhostlockEffect.PickDocument(DocumentRequest.UefiImage))
                AttachOption.VENDOR_BOOT -> onVendorBootImport()
                null -> Unit
            }
        }
    }

    fun onDialogInputChange(value: String) = mutableState.update { it.copy(dialogInput = value) }

    fun onDialogConfirm(value: String) {
        val dialogType = state.value.dialogType
        val renameTarget = state.value.userProfileRenameTarget
        dismissDialog(clearConfirmation = false)
        when {
            renameTarget != null -> renameUserProfile(renameTarget, value)
            dialogType == DialogType.INPUT -> parseUrl(value)
            dialogType == DialogType.CONFIRM -> toggleShizuku(true)
            else -> Unit
        }
    }

    fun onDialogDismiss() = dismissDialog()

    fun onDialogDismissFinished() {
        if (!state.value.dialogVisible) {
            clearDialog()
            if (vendorBootPromptPending) {
                vendorBootPromptPending = false
                promptVendorBootIfNeeded()
            }
        }
    }

    override fun onCleared() {
        repository.close()
        effectChannel.close()
        super.onCleared()
    }

    private suspend fun refreshSnapshot() {
        val snapshot = withContext(Dispatchers.IO) { loadKernelSnapshot() }
        /* Validate the resolved profile here so the run button can grey out. */
        val loaded = withContext(Dispatchers.IO) {
            val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair)
                ?: return@withContext null
            runCatching { profileController.load(snapshot.kernelRelease, pair) }.getOrNull()
        }
        kernelSnapshot = snapshot
        mutableState.update {
            it.copy(
                deviceName = snapshot.deviceName,
                kernelRelease = snapshot.kernelRelease,
                socName = snapshot.socName,
                kernelSupported = snapshot.kernelSupported,
                cpuPairLabels = snapshot.cpuPairLabels,
                cpuPairIndex = snapshot.selectedCpuPair,
                safeModeEnabled = snapshot.safeModeEnabled,
                forceAttackTestEnabled = snapshot.forceAttackTest,
                shizukuEnabled = snapshot.shizukuEnabled,
                shizukuStatus = snapshot.shizukuStatus,
                profileInvalidPaths = loaded?.invalidPaths ?: emptySet(),
                executionHasProfile = loaded?.hasProfile ?: false,
                customCpuPair = loaded?.let(::customCpuPairOf),
                selectedManagerPackage = repository.selectedManagerPackage(),
                exploitChain = repository.exploitChain(),
            )
        }
        refreshTimerRootState()
    }

    private fun importDocuments(uris: List<String>) {
        if (uris.isEmpty() || !beginOperation(showLogSheet = false)) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val documents = linkedMapOf<String, String>()
                uris.forEach { uri ->
                    val name = uri.toUri().lastPathSegment?.let(Uri::decode)
                        ?: uri.substringAfterLast('/')
                    documents[name] = readDocumentUseCase(uri)
                }
                handleImportResult(importOffsetsUseCase(documents), documents)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("import offsets failed: ${error.message}")
                appendLog("result: import failed")
                showNotice(R.string.import_result_title, R.string.import_failed)
            } finally {
                endOperation()
            }
        }
    }

    private suspend fun handleImportResult(
        result: OffsetImportResult,
        documents: Map<String, String>,
    ) {
        when (result) {
            is OffsetImportResult.RequiresOverwrite -> {
                pendingConfirmation = PendingConfirmation.Import(documents)
                showOverwriteDialog(result.releases)
            }

            is OffsetImportResult.Imported -> {
                refreshSnapshot()
                refreshUserProfiles()
                appendLog("profile imported: ${result.releases.joinToString()}")
                appendLog("result: offsets imported successfully")
                val deviceRelease = state.value.kernelRelease
                val matchesDevice = deviceRelease.isEmpty() ||
                        result.releases.any { it == deviceRelease }
                showNotice(
                    R.string.import_result_title,
                    if (matchesDevice) R.string.import_success else R.string.import_no_match,
                )
            }

            OffsetImportResult.AlreadyPresent -> {
                appendLog("result: offsets already present")
                showNotice(R.string.import_result_title, R.string.offsets_already_exist)
            }

            is OffsetImportResult.MissingIncludes -> {
                appendLog("import offsets missing includes: ${result.files.joinToString()}")
                appendLog("result: import failed")
                showNotice(R.string.import_result_title, R.string.import_missing_includes)
            }

            is OffsetImportResult.Failed -> {
                appendLog("import offsets failed: ${result.reason}")
                appendLog("result: import failed")
                showNotice(R.string.import_result_title, R.string.import_failed)
            }
        }
    }

    private fun pickPayload() {
        pendingPayloadPath = null
        pendingXblPath = null
        pendingUefiPath = null
        send(GhostlockEffect.Toast(R.string.parse_pick_payload_hint))
        send(GhostlockEffect.PickDocument(DocumentRequest.PayloadImage))
    }

    private fun pickBoot() {
        pendingBootPath = null
        pendingXblPath = null
        pendingUefiPath = null
        send(GhostlockEffect.PickDocument(DocumentRequest.BootImage))
    }

    /**
     * Runs the parse for whichever source was staged, with whatever images the
     * user attached in the loop. Called by the attachment step's first item, so
     * starting a parse is the same action on every path. A staged vendor_boot
     * is passed through for the MediaTek physical-base path; on vivo/iQOO it
     * was already copied to its staged name and the runtime reads that.
     */
    private fun startPendingParse() {
        parseDialogStage = ParseDialogStage.Mode
        val boot = pendingBootPath
        val payload = pendingPayloadPath
        val url = pendingUrl
        val xbl = pendingXblPath
        val uefi = pendingUefiPath
        val vendorBoot = pendingVendorBootPath
        pendingBootPath = null
        pendingPayloadPath = null
        pendingUrl = null
        pendingXblPath = null
        pendingUefiPath = null
        pendingVendorBootPath = null
        when {
            url != null -> parseUrl(url, xbl, uefi)
            payload != null -> viewModelScope.launch(Dispatchers.IO) {
                runParse(payload, xblPath = xbl, uefiPath = uefi, vendorBootPath = vendorBoot)
            }

            boot != null -> viewModelScope.launch(Dispatchers.IO) {
                runParse(boot, xblPath = xbl, uefiPath = uefi, vendorBootPath = vendorBoot)
            }

            else -> Unit
        }
    }

    private fun stageBoot(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bootPath = readDocumentUseCase.cache(uri, "boot.img")
                pendingBootPath = bootPath
                pendingPayloadPath = null
                pendingUrl = null
                appendLog("boot.img ready: $bootPath")
                /* Ask about attachments before parsing: this is where
                 * vendor_boot.img, xbl_config.img and uefi.img are offered. */
                promptAttach()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun stageXbl(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val xblPath = readDocumentUseCase.cache(uri, "xbl_config.img")
                pendingXblPath = xblPath
                appendLog("xbl_config.img ready: $xblPath")
                promptAttach()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun stageUefi(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val uefiPath = readDocumentUseCase.cache(uri, "uefi.img")
                pendingUefiPath = uefiPath
                appendLog("uefi.img ready: $uefiPath")
                promptAttach()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private companion object {
        const val VendorBootFileName = "vendor_boot.img"

        /** A real vendor_boot is tens of megabytes; below this it is not one. */
        const val MinVendorBootBytes = 64L * 1024

        const val VendorBootMagic = "VNDRBOOT"

        /**
         * First bytes of the file, or "" when they cannot be read.
         *
         * Reads until the buffer is full: one `read()` may return fewer bytes
         * than asked for, and treating that as a short file would reject a
         * valid image at random.
         */
        fun readMagic(path: String, size: Int = VendorBootMagic.length): String = runCatching {
            val header = ByteArray(size)
            java.io.File(path).inputStream().use { input ->
                var filled = 0
                while (filled < size) {
                    val read = input.read(header, filled, size - filled)
                    if (read <= 0) return@runCatching ""
                    filled += read
                }
            }
            String(header, Charsets.US_ASCII)
        }.getOrDefault("")
    }

    /**
     * Stages vendor_boot.img: keeps the cached path for the parse (MediaTek
     * physical base) and copies it to the staged name the native runtime reads
     * (vivo/iQOO vr.ko probe). The magic and size are checked before the image
     * is trusted: a boot.img or init_boot.img picked by mistake would otherwise
     * sit under a name the runtime reads, and the failure would only surface
     * mid-run.
     */
    private fun stageVendorBoot(uri: String) {
        markVendorBootImported()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val vbPath = readDocumentUseCase.cache(uri, VendorBootFileName)
                val sizeBytes = java.io.File(vbPath).length()
                appendLog("vendor_boot.img ready: $vbPath ($sizeBytes bytes)")
                val magic = readMagic(vbPath)
                if (magic != VendorBootMagic || sizeBytes < MinVendorBootBytes) {
                    java.io.File(vbPath).delete()
                    vendorBootImported = false
                    appendLog("vendor_boot rejected: magic=\"$magic\" size=$sizeBytes")
                    appendLog("result: not a vendor_boot image")
                    showNotice(R.string.parse_result_title, R.string.vivo_vendor_boot_invalid)
                    return@launch
                }
                pendingVendorBootPath = vbPath
                vendorBootImported = true
                repository.stageVendorBootImage(vbPath)
                appendLog("vendor_boot staged: vr.ko tag offsets will be parsed from it at run time")
                send(GhostlockEffect.Toast(R.string.vivo_vendor_boot_imported))
                /* Mid-parse: hand control back to the attachment step so xbl /
                 * uefi can still be added before the parse runs. */
                if (parseDialogStage == ParseDialogStage.Attach) promptAttach()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("vendor_boot error: ${error.message}")
                appendLog("result: vendor_boot import failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun stagePayload(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val payloadPath = readDocumentUseCase.cache(uri, "payload.bin")
                pendingPayloadPath = payloadPath
                pendingBootPath = null
                pendingUrl = null
                appendLog("payload.bin ready: $payloadPath")
                promptAttach()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun parseUrl(value: String) {
        val url = value.trim()
        if (url.isEmpty() || !(url.startsWith("http://") || url.startsWith("https://"))) {
            appendLog("error: invalid OTA URL: $url")
            appendLog("result: parse failed")
            showNotice(R.string.parse_result_title, R.string.parse_failed_url)
            return
        }
        pendingUrl = url
        pendingBootPath = null
        pendingPayloadPath = null
        appendLog("OTA link ready: $url")
        /* Attachments first: a full package already carries vendor_boot and a
         * physical-load source, so the user usually just confirms. */
        promptAttach()
    }

    /** Confirm path used by [startPendingParse] once the URL was staged. */
    private fun parseUrl(url: String, xblPath: String?, uefiPath: String?) {
        appendLog("parse OTA: $url")
        viewModelScope.launch(Dispatchers.IO) {
            runParse(url, xblPath = xblPath, uefiPath = uefiPath)
        }
    }

    /* ---- vivo/iQOO vendor_boot prompt ---- */

    /** Absolute path of a staged vendor_boot.img, or null when there is none. */
    private fun stagedVendorBoot(): String? =
        runCatching { repository.stagedImagePath(VendorBootFileName) }.getOrNull()

    /**
     * Marks an already staged vendor_boot.img as imported and reports it once,
     * so a restart does not ask for a file the app still has.
     */
    private fun adoptStagedVendorBoot() {
        if (vendorBootImported) return
        if (stagedVendorBoot() != null) {
            vendorBootImported = true
            viewModelScope.launch(Dispatchers.IO) {
                appendLog("vendor_boot.img already staged; vr.ko probe will use it")
            }
        }
    }

    /** Set once the user picks a vendor_boot image (success or failure). */
    private fun markVendorBootImported() {
        vendorBootImported = true
        vendorBootPromptPending = false
    }

    /** vivo/iQOO without a vendor_boot image: ask for it. Called after a parse
     * produced a profile — that is when the image starts to matter. The request
     * queues itself when another dialog is on screen and is shown after it
     * closes, so the two never replace each other. Once per process. */
    fun promptVendorBootIfNeeded() {
        if (!looksLikeVivoIqoo() || vendorBootImported) return
        adoptStagedVendorBoot()
        if (vendorBootImported) return
        vendorBootPromptPending = true
        if (!state.value.dialogVisible) showVendorBootPrompt()
    }

    private fun showVendorBootPrompt() {
        vendorBootPromptPending = false
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.VENDOR_BOOT,
                dialogTitleRes = R.string.vivo_vendor_boot_prompt_title,
                dialogMessageRes = R.string.vivo_vendor_boot_prompt_message,
                dialogConfirmLabelRes = R.string.vivo_vendor_boot_import,
                dialogDocUrl = null,
            )
        }
    }

    /** Confirm button of the vendor_boot prompt: open the picker. */
    fun onVendorBootImport() {
        dismissDialog()
        send(GhostlockEffect.PickDocument(DocumentRequest.VendorBootImage))
    }

    /**
     * vivo / iQOO detection.
     *
     * `Build.MANUFACTURER` / `Build.BRAND` are the authoritative fields (iQOO
     * handsets report manufacturer "vivo" with brand "iQOO"), so they are
     * checked first. The SoC / device names are only a fallback.
     */
    private fun looksLikeVivoIqoo(): Boolean {
        val identity = listOf(
            android.os.Build.MANUFACTURER,
            android.os.Build.BRAND,
            kernelSnapshot?.deviceName,
            kernelSnapshot?.socName,
        ).joinToString(" ").lowercase(Locale.ROOT)
        return identity.contains("vivo") || identity.contains("iqoo")
    }

    /** Confirm/notice popup for an extractor outcome; unlike a Toast it waits
     * for the user and can link the matching documentation page. */
    private fun showNotice(titleRes: Int, messageRes: Int, docUrl: String? = null) {
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.NOTICE,
                dialogTitleRes = titleRes,
                dialogMessageRes = messageRes,
                dialogDocUrl = docUrl,
                dialogConfirmLabelRes = R.string.dialog_dismiss,
            )
        }
    }

    private fun isMediaTek(): Boolean {
        val soc = kernelSnapshot?.socName?.lowercase(Locale.ROOT).orEmpty()
        return soc.contains("mediatek") || soc.contains("mtk") ||
                soc.contains("dimensity") || soc.contains("helio")
    }

    private fun mediatekDocUrl(): String =
        "https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/" +
                if (Locale.getDefault().language == "zh") "MEDIATEK_ZH.md" else "MEDIATEK.md"

    private suspend fun runParse(
        input: String,
        xblPath: String? = null,
        uefiPath: String? = null,
        vendorBootPath: String? = null,
        overwrite: Boolean = false,
    ) {
        if (!beginOperation()) return
        try {
            when (
                val result = parseSourceUseCase(
                    input, xblPath, uefiPath, vendorBootPath, overwrite, ::appendLog,
                )
            ) {
                is ParseResult.RequiresOverwrite -> {
                    pendingConfirmation =
                        PendingConfirmation.Parse(input, xblPath, uefiPath, vendorBootPath)
                    showOverwriteDialog(result.releases)
                }

                is ParseResult.Parsed -> {
                    refreshSnapshot()
                    refreshUserProfiles()
                    appendLog("offsets exported: ${result.releases.joinToString()}")
                    appendLog("result: offsets parsed successfully")
                    /* Auto-load the just-saved document so the parsed profile
                     * takes effect without a manual trip to the profile list. */
                    if (result.documentName != null) {
                        appendLog("auto-loading parsed profile: ${result.documentName}")
                        selectUserProfile(result.documentName)
                    }
                    if (result.missing.isNotEmpty()) {
                        appendLog(
                            "warning: missing ${result.missing.joinToString()}; " +
                                    "run the MediaTek extractor or attach xbl_config.img / uefi.img",
                        )
                        val mediaTek = isMediaTek()
                        showNotice(
                            titleRes = R.string.parse_result_title,
                            messageRes = if (mediaTek) {
                                R.string.parse_missing_phys_mediatek
                            } else {
                                R.string.parse_missing_phys_hint
                            },
                            docUrl = if (mediaTek) mediatekDocUrl() else null,
                        )
                    } else if (result.documentName == null) {
                        showNotice(R.string.parse_result_title, R.string.parse_success)
                    }
                    /* The profile is in place: this is when a vivo/iQOO device
                     * needs to know that vendor_boot.img was not part of the
                     * parse, because the runtime probe reads the vr.ko tag
                     * offsets out of it. Queued behind the notice above when one
                     * is showing. */
                    promptVendorBootIfNeeded()
                }

                ParseResult.AlreadyPresent -> {
                    appendLog("result: offsets already present")
                    showNotice(R.string.parse_result_title, R.string.offsets_already_exist)
                }

                is ParseResult.Failed -> {
                    result.reason?.let { appendLog("parse failed: $it") }
                    appendLog("result: ${parseFailureResult(result.code)}")
                    showNotice(R.string.parse_result_title, parseFailureToast(result.code))
                }
            }
        } finally {
            endOperation()
        }
    }

    fun onOverwriteConfirm() {
        mutableState.update { it.copy(overwriteDialogVisible = false, overwriteMessage = "") }
        confirmPendingOperation()
    }

    fun onOverwriteDismiss() {
        pendingConfirmation = null
        running = false
        appendLog("result: overwrite cancelled")
        mutableState.update {
            it.copy(
                overwriteDialogVisible = false,
                overwriteMessage = "",
                running = false,
                executionSheetDismissible = true,
            )
        }
    }

    private fun confirmPendingOperation() {
        val confirmation = pendingConfirmation ?: return
        pendingConfirmation = null
        when (confirmation) {
            is PendingConfirmation.Import -> {
                if (!beginOperation(showLogSheet = false)) return
                viewModelScope.launch(Dispatchers.IO) {
                    try {
                        handleImportResult(
                            importOffsetsUseCase.overwrite(confirmation.documents),
                            confirmation.documents,
                        )
                    } finally {
                        endOperation()
                    }
                }
            }

            is PendingConfirmation.Parse -> viewModelScope.launch(Dispatchers.IO) {
                runParse(
                    confirmation.input,
                    confirmation.xblPath,
                    confirmation.uefiPath,
                    confirmation.vendorBootPath,
                    overwrite = true,
                )
            }
        }
    }

    private fun showOverwriteDialog(releases: List<String>) {
        mutableState.update {
            it.copy(
                overwriteDialogVisible = true,
                overwriteMessage = overwriteSummary(releases),
                /* The confirmation must be the only overlay on screen; a log
                 * sheet behind it would swallow its taps. */
                executionSheetVisible = false,
            )
        }
    }

    /** Keeps the confirmation readable when a document carries many releases. */
    private fun overwriteSummary(releases: List<String>): String {
        val head = releases.take(OverwriteSummaryLimit).joinToString("\n")
        val rest = releases.size - OverwriteSummaryLimit
        return if (rest > 0) "$head\n… (+$rest)" else head
    }

    private fun dismissDialog(clearConfirmation: Boolean = true) {
        if (clearConfirmation) pendingConfirmation = null
        mutableState.update {
            it.copy(
                dialogVisible = false,
            )
        }
    }

    private fun clearDialog() {
        mutableState.update {
            it.copy(
                dialogVisible = false,
                dialogType = DialogType.NONE,
                dialogTitleRes = 0,
                dialogMessage = "",
                dialogMessageRes = 0,
                dialogItems = emptyList(),
                dialogItemResIds = emptyList(),
                dialogCurrentItemIndex = -1,
                dialogInput = "",
                dialogConfirmLabelRes = R.string.parse_start,
                dialogDocUrl = null,
                userProfileRenameTarget = null,
            )
        }
    }

    private fun appendLog(line: String) {
        /* The final result lines are Kotlin-side; tag them so they read as <k>. */
        val tagged = if (line.startsWith("result:")) "<k> $line" else line
        val entry = formatLog(tagged)
        val uiLine = GhostlockLogLine(entry.text, toneColor(entry.tone))
        mutableState.update { it.copy(logLines = it.logLines + uiLine) }
    }

    private fun beginOperation(showLogSheet: Boolean = true): Boolean {
        if (running) return false
        running = true
        mutableState.update {
            if (showLogSheet) {
                it.copy(
                    running = true,
                    executionSheetVisible = true,
                    executionSheetDismissible = false,
                )
            } else {
                it.copy(running = true)
            }
        }
        return true
    }

    private fun endOperation() {
        running = false
        mutableState.update { it.copy(running = false, executionSheetDismissible = true) }
    }

    private fun send(effect: GhostlockEffect) {
        effectChannel.trySend(effect)
    }

    private fun toneColor(tone: LogTone): Int = when (tone) {
        LogTone.Error -> 0xFFFF6B6B.toInt()
        LogTone.Success -> 0xFF5FD68A.toInt()
        LogTone.Warning -> 0xFFFFC94D.toInt()
        LogTone.Progress -> 0xFF60A5FA.toInt()
        LogTone.Kotlin -> 0xFF5EEAD4.toInt()
        LogTone.Shizuku -> 0xFFC084FC.toInt()
        LogTone.Default -> -1
    }

    private fun parseFailureToast(code: Int): Int = when (code) {
        3, 4 -> R.string.parse_failed_route
        5 -> R.string.parse_failed_kallsyms
        6 -> R.string.parse_failed_fixed
        -1 -> R.string.parse_timeout
        else -> R.string.parse_failed
    }

    private fun parseFailureResult(code: Int): String = when (code) {
        3, 4 -> "exploit chain unsupported by this kernel"
        5 -> "kernel symbol table could not be recovered"
        6 -> "kernel has fixed the vulnerability"
        -1 -> "parse timed out"
        else -> "parse failed"
    }

    private sealed interface PendingConfirmation {
        data class Import(val documents: Map<String, String>) : PendingConfirmation
        data class Parse(
            val input: String,
            val xblPath: String?,
            val uefiPath: String?,
            val vendorBootPath: String? = null,
        ) : PendingConfirmation
    }
}

/* ---- ic-syms 编辑页的字段解析（文件级 helper，纯函数便于单测） ---- */

/** The hard target symbol the edit page exposes next to the geometry. */
internal const val TimerRootHardTarget = "__tracepoint_sys_exit"

/**
 * Parses the staged ic-syms text into the editable fields: every recognized
 * `off.<key>` geometry line (essential keys first, then optional ones) plus the
 * hard target symbol. Line order inside the file is irrelevant — the save path
 * matches keys, not positions.
 */
internal fun timerRootEditFieldsOf(text: String): List<TimerRootSymsField> {
    val geometry = linkedMapOf<String, String>()
    var hardTarget: String? = null
    text.lineSequence().forEach { raw ->
        val line = raw.trimEnd('\r', '\n')
        when {
            line.startsWith("off.") -> {
                val key = line.substringAfter("off.").substringBefore('=')
                val value = line.substringAfter('=', "")
                if (key in TimerRootGeometry.KNOWN_KEYS && value.isNotBlank()) {
                    geometry[key] = value.trim()
                }
            }

            line.startsWith("$TimerRootHardTarget=") ->
                hardTarget = line.substringAfter('=', "").trim()
        }
    }
    val ordered = TimerRootGeometry.ESSENTIAL_KEYS.filter { it in geometry } +
        (geometry.keys - TimerRootGeometry.ESSENTIAL_KEYS.toSet())
    return buildList {
        ordered.forEach { key ->
            add(
                TimerRootSymsField(
                    key = key,
                    label = "off.$key",
                    value = geometry[key].orEmpty(),
                    isGeometry = true,
                ),
            )
        }
        hardTarget?.let {
            add(
                TimerRootSymsField(
                    key = TimerRootHardTarget,
                    label = TimerRootHardTarget,
                    value = it,
                    isGeometry = false,
                ),
            )
        }
    }
}

/**
 * Writes the edited field values back into the table text: each `off.<key>=`
 * line and the hard target line is replaced in place; every other line (the
 * symbol table itself, banners, comments) is preserved verbatim.
 */
internal fun applyTimerRootEdits(text: String, fields: List<TimerRootSymsField>): String {
    val byKey = fields.associateBy { it.key }
    return text.lineSequence().joinToString(separator = "\n") { raw ->
        val line = raw.trimEnd('\r', '\n')
        when {
            line.startsWith("off.") -> {
                val key = line.substringAfter("off.").substringBefore('=')
                val edited = byKey[key]?.value
                if (key in TimerRootGeometry.KNOWN_KEYS && !edited.isNullOrBlank()) {
                    "off.$key=$edited"
                } else {
                    line
                }
            }

            line.startsWith("$TimerRootHardTarget=") -> {
                val edited = byKey[TimerRootHardTarget]?.value
                if (!edited.isNullOrBlank()) "$TimerRootHardTarget=$edited" else line
            }

            else -> line
        }
    }
}
