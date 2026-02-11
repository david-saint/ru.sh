## 2024-05-22 - [Optimized History Rotation]
**Learning:** `BufReader::lines()` allocates a new `String` for every line, which causes massive allocation churn (O(N)) when processing large log files only to discard most of them.
**Action:** Use `read_line` with a `VecDeque<String>` ring buffer and a "spare" `String` to recycle allocations. This reduces allocations from O(total_lines) to O(kept_lines). Also, use `trim_end()` with `writeln!` when writing back to ensure consistent line endings without double newlines.

## 2024-06-03 - [Optimized API Retry Logic]
**Learning:** Re-creating a `reqwest::RequestBuilder` using a closure inside a retry loop causes redundant JSON serialization for every attempt, which is CPU-intensive.
**Action:** Construct the `RequestBuilder` once before the loop and use `try_clone()` (which clones the internal `Bytes` buffer) for subsequent retries. This reduces the overhead from O(N * serialization) to O(1 * serialization + N * memcpy), achieving a ~38x speedup in synthetic benchmarks.
