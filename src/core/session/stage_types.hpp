#ifndef GHOSTLOCK_STAGE_TYPES_HPP
#define GHOSTLOCK_STAGE_TYPES_HPP

#include <cstdint>

namespace ghostlock::session {
    /* Outcome of one orchestration stage. Failed maps to exit code 1, Continue
     * proceeds to the next stage and Done stops with exit code 0 (diagnostics). */
    enum class StageResult {
        Failed,
        Continue,
        Done,
    };

    /* Outcome of one W2/W3 victim round. */
    enum class VictimRound {
        Failed,
        Retry,
        Rooted,
    };

    /* State handed from the W2/W3 victim chain to the frontend handoff
     * (Batch 4 review P4). Ownership contract:
     *   - session.victim / session.parked_victim* are the authority for the
     *     child pid, its pipes and the parked child;
     *   - VictimChain is a single-threaded, transferred stage summary: written
     *     by the backend before run() returns it and read by the frontend
     *     afterwards on the same thread (ever_rooted = a child was rooted,
     *     seccomp_ok = W3 result, child_alive = last observation). The handoff
     *     still acts on the session's fds/pid; the chain only selects the path,
     *     so there is no stale-state window. If concurrency is ever introduced,
     *     the chain must become read-only accessors over the session. */
    struct VictimChain {
        int32_t child_alive = 1;
        int32_t seccomp_ok = 0;
        int32_t ever_rooted = 0;
        /* W3 leaf direction learned by the comm probe: -1 unknown, 0 = a
 * leaf write lands on [target], 1 = [target+8]. Set by the probe that
 * now runs inside w2() BEFORE the credential write (an unprivileged
 * child is cheap to retire), reused by every later W3 round so the
 * probe write is paid at most once per run. */
        int32_t leaf_dir = -1;
    };

    using write_stage_verify_fn = int32_t (*)(void *context);
} // namespace ghostlock::session

#endif
