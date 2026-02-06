## 2025-02-18 - Sanitize Allocation Optimization
**Learning:** Text sanitization functions often process strings that are already safe. Returning `Cow<'_, str>` instead of `String` allows checking for safe content and returning a borrowed slice, avoiding allocation in the common case.
**Action:** When writing string transformation functions, consider if the "no-op" case is common. If so, return `Cow` to allow zero-copy returns.
