# Libfabric plugin performance review

This note summarizes hotspots and concrete optimizations for the current libfabric backend implementation.

## 1) Avoid busy-spin in background progress loops

**Observed**
- CM thread loops continuously and only sleeps for `10ns` when blocking CQ read is unavailable.
- Data progress loop polls repeatedly and sleeps a fixed delay only when no completion is found.

**Why it matters**
- On low-traffic periods this can consume high CPU for little useful work.
- On oversubscribed hosts it can steal cycles from app threads and worsen tail latency.

**Recommended changes**
- Use adaptive backoff in both loops (e.g., spin a few iterations, then `sleep_for(1-50us)` with cap).
- Prefer `fi_cq_sread` with provider-supported timeout for both control and (where possible) data paths.
- Add counters for empty polls vs. completions to tune delay automatically.

## 2) Drain multiple CQ entries per poll

**Observed**
- `progressCompletionQueue()` reads at most one completion (`count=1`) per call.

**Why it matters**
- Under bursty load, per-entry lock/read overhead grows and completions can backlog.

**Recommended changes**
- Read batches (`fi_cq_read(cq, entries, N)`) and process all returned completions.
- Keep fast-path stack buffer (e.g., 8-32 entries) and fall back to single-entry only if needed.

## 3) Reduce debug logging in hot paths

**Observed**
- Per-descriptor transfer setup emits several `NIXL_DEBUG` messages.
- Completion and rail progress paths also emit frequent logs.

**Why it matters**
- String formatting and stream I/O can be measurable at high message rates.

**Recommended changes**
- Gate verbose logs behind a stricter runtime level or sampling.
- Keep one summary log per transfer instead of per descriptor/chunk by default.

## 4) Replace global transfer-ID matching map key

**Observed**
- Pending completion tracking uses `std::map<uint16_t, PendingNotification>` keyed only by 16-bit xfer ID.
- Xfer IDs wrap and are shared globally.

**Why it matters**
- Collision risk under long runs / high concurrency can produce incorrect matching work and extra map churn.
- `std::map` introduces O(logN) overhead in hot completion paths.

**Recommended changes**
- Use composite key `(remote_agent, xfer_id)` or `(agent_idx, xfer_id)`.
- Switch to `absl::flat_hash_map`/`std::unordered_map` to reduce lookup overhead.
- Add generation/epoch bits to xfer IDs if protocol space allows.

## 5) Avoid repeated allocation/copy in connection setup and notifications

**Observed**
- Control messages repeatedly allocate request buffers and memcpy serialized payloads.

**Why it matters**
- Connection-heavy or notification-heavy workloads pay avoidable allocation and copy costs.

**Recommended changes**
- Cache serialized local connection info until topology changes.
- Reuse fixed control buffers for constant-size notifications.
- Consider a small per-thread control-request cache to reduce lock contention.

## 6) Improve striping policy from static threshold to adaptive policy

**Observed**
- Striping toggles using one static byte threshold.

**Why it matters**
- Best threshold depends on provider, rail count, GPU/NUMA topology, and current load.

**Recommended changes**
- Add adaptive policy based on recent completion latency and throughput per rail.
- Maintain per-rail outstanding depth and schedule to the least-loaded eligible rail for small/medium transfers.
- Keep static threshold as fallback override.

## 7) Minimize lock overhead in active-rail progression

**Observed**
- `progressActiveDataRails()` copies active rail IDs into a temporary vector each call.

**Why it matters**
- Poll loop may call this very frequently; repeated allocations/copies can add overhead.

**Recommended changes**
- Store active rails in fixed-size bitset or small-vector snapshot reused across calls.
- Use lock-free/RCU-like snapshot for read-mostly polling path.

## 8) Fix lock handling in `connect()` before performance tuning

**Observed**
- `connect()` manually invokes the destructor of `std::lock_guard` to release lock early.

**Why it matters**
- This is undefined behavior and can cause unpredictable runtime overhead/failures.

**Recommended changes**
- Replace with `std::unique_lock` and explicit `.unlock()` before `establishConnection()`.

---

## Suggested benchmarking plan

1. Add lightweight counters:
   - CQ polls, empty polls, completions processed, average batch size.
   - request-pool expansion events and active request depth.
2. Run A/B benchmarks per provider (`efa`, `verbs;ofi_rxm`, `tcp`):
   - small messages (4KB-64KB), medium (256KB-2MB), large (8MB+).
   - DRAM and VRAM separately.
3. Track:
   - throughput (GB/s), p50/p95/p99 latency, CPU/core utilization.
4. Roll out improvements in this order:
   - (a) progress loop backoff + batched CQ reads,
   - (b) log reduction in hot paths,
   - (c) composite-key pending map and hash-map migration,
   - (d) adaptive striping.
