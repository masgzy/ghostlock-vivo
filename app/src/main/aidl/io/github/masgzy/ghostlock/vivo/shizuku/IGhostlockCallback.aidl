package io.github.masgzy.ghostlock.vivo.shizuku;

oneway interface IGhostlockCallback {
    void onLog(String line);
    void onComplete(int exitCode);
}
