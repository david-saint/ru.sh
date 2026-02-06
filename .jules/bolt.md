## 2025-02-18 - Sanitize Allocation Optimization
**Learning:** Text sanitization functions often process strings that are already safe. Returning `Cow<'_, str>` instead of `String` allows checking for safe content and returning a borrowed slice, avoiding allocation in the common case.
**Action:** When writing string transformation functions, consider if the "no-op" case is common. If so, return `Cow` to allow zero-copy returns.

## 2025-05-20 - History Rotation Memory Optimization
**Learning:** Truncating large files by reading all lines into a `Vec` causes massive memory spikes (O(N)). Using a `VecDeque` ring buffer with fixed capacity reduces peak memory usage to O(K) where K is the number of lines to keep.
**Action:** When processing files where only a subset of data is needed (e.g., tail), use a fixed-size buffer or sliding window instead of loading the entire file.
