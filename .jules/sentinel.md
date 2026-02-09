## 2024-05-23 - Outdated Device Regex
**Vulnerability:** The regex patterns for detecting dangerous disk operations (`mkfs`, `dd`, `>`) only matched legacy `/dev/sd[a-z]` devices, completely missing modern NVMe (`/dev/nvme0n1`) and MMC (`/dev/mmcblk0`) devices.
**Learning:** Security regexes must be updated to reflect modern hardware standards. Hardcoding `sd[a-z]` is a common legacy pattern that leaves newer systems vulnerable.
**Prevention:** Use more inclusive regexes for device names, or better yet, abstract device detection logic to a centralized function that is easier to maintain and update.

## 2025-05-19 - Regex Bypass via Trailing Comments
**Vulnerability:** The regex for detecting `rm -rf /` used `\s*($|[;&|])` to ensure the command ended or was separated. This failed to account for trailing comments (e.g., `rm -rf / # comment`) where the comment character `#` is a valid shell separator/terminator for the command.
**Learning:** When using regex for security checks on shell commands, "whitespace" (`\s`) typically acts as a separator. Any whitespace following a dangerous argument usually means the argument is complete and the danger is present, regardless of what follows (unless it's part of the path, which `/` is not). Relying on explicit terminators like `;`, `|`, `&` without including whitespace or comments (`#`) is brittle.
**Prevention:** Treat whitespace as a terminator for command arguments in security regexes. The pattern `(\s|[;&|]|$)` is more robust than looking for explicit control operators after optional whitespace.

## 2025-05-27 - Markdown Code Block Execution
**Vulnerability:** The `strip_code_blocks` function extracted the entire content after the first opening fence ` ``` ` without stopping at the first closing fence. This allowed trailing text (e.g., "Explanation: ...") to be included in the script and executed, creating a potential RCE vulnerability if the LLM hallucinates commands in the explanation.
**Learning:** LLM outputs are untrusted and unpredictable. When extracting structured data (like code blocks) from LLM responses, always strictly parse the delimiters and discard everything outside the expected structure. Do not assume the LLM will only output the requested format.
**Prevention:** Use robust parsing logic that identifies both start and end delimiters of the desired content. Treat everything outside these delimiters as potentially malicious or garbage data and discard it.

## 2025-05-27 - Regex Bypass via Immediate Comment
**Vulnerability:** The regex for `rm -rf /` allowed bypassing detection by appending a comment character `#` immediately after the path (e.g., `rm -rf /#`), as `#` was not included in the terminator set `(\s|[;&|]|$)`.
**Learning:** In shell, `#` can start a comment immediately after a token without whitespace. Security regexes must account for `#` as a terminator even without preceding whitespace.
**Prevention:** Include `#` in the set of terminators: `(\s|[;&|#]|$)`.

## 2025-05-29 - Regex Bypass via Argument Reordering
**Vulnerability:** The regex for detecting `rm -rf /` only matched if the flags (`-rf`) appeared *before* the target path (e.g., `rm -rf /`). This failed to detect cases where flags appeared after the path (`rm / -rf`) or were mixed (`rm -v / -rf`), which are valid shell syntax.
**Learning:** Regex-based security checks must account for flexible command-line syntax where flags and arguments can be interleaved or reordered. Rigid assumptions about argument order create easy bypasses.
**Prevention:** Use multiple regex patterns or more flexible patterns that detect dangerous flags anywhere in the command string relative to the target argument, ensuring they are part of the same command (not separated by `;` or `|`).
