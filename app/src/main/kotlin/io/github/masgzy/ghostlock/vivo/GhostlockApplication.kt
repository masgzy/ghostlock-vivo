package io.github.masgzy.ghostlock.vivo

import android.app.Application
import io.github.masgzy.ghostlock.vivo.data.AndroidGhostlockRepository
import io.github.masgzy.ghostlock.vivo.domain.repository.GhostlockRepository

/** Application composition root. It is the only place that binds data implementations to domain ports. */
class GhostlockApplication : Application() {
    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)
}
