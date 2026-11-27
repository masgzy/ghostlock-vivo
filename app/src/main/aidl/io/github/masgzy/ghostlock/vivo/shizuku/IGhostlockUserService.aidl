package io.github.masgzy.ghostlock.vivo.shizuku;

import io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockCallback;
import io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockStatusCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 2;
    void runExploitAsManager(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, @nullable String managerPackage, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 3;
    /* managerPackage: the app's chosen root manager, so the shell-side auto
     * resolution starts from the same package the user picked instead of the
     * built-in order. */
    void runTimerRoot(@nullable String managerApk, @nullable String ksudEntry, @nullable String managerPackage, @nullable String symsTable, boolean safeMode, boolean allowAnyKernel, IGhostlockCallback callback) = 4;
    void pushTimerRootBinary(in byte[] chunk, int offset, int total) = 5;
    /* Drops the shell-side copy of an imported t98260 (t98260-user plus the
     * staged t98260 of the last run). Called when the app-side import is
     * removed and as a reconcile step before every run without an import —
     * the shell-side file outlives the app-side one and used to win the
     * staging precedence forever. */
    void clearTimerRootBinary() = 6;
}
