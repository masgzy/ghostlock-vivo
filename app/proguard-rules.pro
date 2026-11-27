# Shizuku binds GhostlockUserService by component name and talks over the
# generated AIDL stubs; R8 must keep both sides in release builds.
-keep class io.github.masgzy.ghostlock.vivo.shizuku.GhostlockUserService { *; }
-keep interface io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockUserService { *; }
-keep interface io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockCallback { *; }
-keep class io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockUserService$Stub { *; }
-keep class io.github.masgzy.ghostlock.vivo.shizuku.IGhostlockCallback$Stub { *; }
