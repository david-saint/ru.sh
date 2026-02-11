## 2024-05-22 - [Optimized History Rotation]
**Learning:** `BufReader::lines()` allocates a new `String` for every line, which causes massive allocation churn (O(N)) when processing large log files only to discard most of them.
**Action:** Use `read_line` with a `VecDeque<String>` ring buffer and a "spare" `String` to recycle allocations. This reduces allocations from O(total_lines) to O(kept_lines). Also, use `trim_end()` with `writeln!` when writing back to ensure consistent line endings without double newlines.

## 2024-05-24 - [Optimized Usage Reset Check]
**Learning:** `Utc::now().format().to_string()` allocates a new string on every call, which is expensive when checking dates frequently.
**Action:** Replaced string formatting and comparison with `chrono::NaiveDate` parsing and `Datelike` integer comparisons. This avoids heap allocations entirely in the common path (when dates match), resulting in a ~35% speedup for the `reset_if_needed` check.
