## 2024-05-22 - [Optimized History Rotation]
**Learning:** `BufReader::lines()` allocates a new `String` for every line, which causes massive allocation churn (O(N)) when processing large log files only to discard most of them.
**Action:** Use `read_line` with a `VecDeque<String>` ring buffer and a "spare" `String` to recycle allocations. This reduces allocations from O(total_lines) to O(kept_lines). Also, use `trim_end()` with `writeln!` when writing back to ensure consistent line endings without double newlines.

## 2024-05-23 - [Optimized Date Comparisons]
**Learning:** Storing dates as Strings and parsing/formatting them repeatedly for daily/monthly limits (which runs on every CLI execution) caused unnecessary allocations and string formatting overhead.
**Action:** Replaced `Option<String>` with `Option<chrono::NaiveDate>` in `UsageStats`. This allows `serde` to handle (de)serialization efficiently while enabling zero-allocation integer comparisons for date logic. Redundant derived fields (like `last_request_month`) should be removed to save space and processing time.
