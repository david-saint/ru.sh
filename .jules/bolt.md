## 2024-05-22 - [Optimized History Rotation]
**Learning:** `BufReader::lines()` allocates a new `String` for every line, which causes massive allocation churn (O(N)) when processing large log files only to discard most of them.
**Action:** Use `read_line` with a `VecDeque<String>` ring buffer and a "spare" `String` to recycle allocations. This reduces allocations from O(total_lines) to O(kept_lines). Also, use `trim_end()` with `writeln!` when writing back to ensure consistent line endings without double newlines.

## 2024-06-03 - [Optimized API Retry Logic]
**Learning:** Re-creating a `reqwest::RequestBuilder` using a closure inside a retry loop causes redundant JSON serialization for every attempt, which is CPU-intensive.
**Action:** Construct the `RequestBuilder` once before the loop and use `try_clone()` (which clones the internal `Bytes` buffer) for subsequent retries. This reduces the overhead from O(N * serialization) to O(1 * serialization + N * memcpy), achieving a ~38x speedup in synthetic benchmarks.

## 2024-05-23 - [Optimized Date Comparisons]
**Learning:** Storing dates as Strings and parsing/formatting them repeatedly for daily/monthly limits (which runs on every CLI execution) caused unnecessary allocations and string formatting overhead.
**Action:** Replaced `Option<String>` with `Option<chrono::NaiveDate>` in `UsageStats`. This allows `serde` to handle (de)serialization efficiently while enabling zero-allocation integer comparisons for date logic. Redundant derived fields (like `last_request_month`) should be removed to save space and processing time.

## 2024-05-22 - [Optimized String Splitting in Safety Analysis]
**Learning:** `split_shell_commands` and `split_shell_words` in `safety.rs` were allocating `String`s for every command and word (O(N)), dominating the runtime of safety checks.
**Action:** Refactored `split_shell_commands` to return `Vec<&str>` (borrowed slices) and `split_shell_words` to return `Vec<Cow<str>>` (allocating only when quotes are stripped). This reduced allocations significantly and improved benchmark performance by ~22%. Use `Cow` for tokenization when modification is conditional.

## 2026-02-25 - [Lazy API Key Resolution]
**Learning:** Fetching environment variables and cloning configuration strings eagerly in `resolve_api_key` causes redundant syscalls and allocations even when the API key is provided via CLI flags.
**Action:** Implemented lazy evaluation using `.or_else()` closures. This ensures `env::var()` and `config.api_key.clone()` are only executed if higher-precedence sources are missing. Synthetic benchmarks showed a ~4.5x speedup (27ms -> 6ms for 100k iterations) in the CLI-provided path.
