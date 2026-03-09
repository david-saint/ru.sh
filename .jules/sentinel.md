## 2026-03-07 - Fix unwrap panic vulnerability on display mask
**Vulnerability:** The function `mask_api_key_for_display` previously called `.unwrap()` when locating the start index of the suffix for the masked key (`api_key.char_indices().rev().nth(SUFFIX_CHARS - 1).unwrap()`).
**Learning:** If a string is shorter than `SUFFIX_CHARS` (or manipulated such that the assumed threshold check was inaccurate), this line panics. A panic in this context means a denial-of-service or app crash on specific input or config display, violating the "fail securely" principle.
**Prevention:** Avoid `.unwrap()` on string index operations or string lookups in production paths. Always use safe fallbacks like `match` or `unwrap_or()` (returning a generic masked string like `"[set]"` here).
