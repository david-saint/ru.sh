## 2024-05-22 - [Optimized History Rotation]
**Learning:** `BufReader::lines()` allocates a new `String` for every line, which causes massive allocation churn (O(N)) when processing large log files only to discard most of them.
**Action:** Use `read_line` with a `VecDeque<String>` ring buffer and a "spare" `String` to recycle allocations. This reduces allocations from O(total_lines) to O(kept_lines). Also, use `trim_end()` with `writeln!` when writing back to ensure consistent line endings without double newlines.

## 2024-05-22 - [Optimized String Splitting in Safety Analysis]
**Learning:** `split_shell_commands` and `split_shell_words` in `safety.rs` were allocating `String`s for every command and word (O(N)), dominating the runtime of safety checks.
**Action:** Refactored `split_shell_commands` to return `Vec<&str>` (borrowed slices) and `split_shell_words` to return `Vec<Cow<str>>` (allocating only when quotes are stripped). This reduced allocations significantly and improved benchmark performance by ~22%. Use `Cow` for tokenization when modification is conditional.
