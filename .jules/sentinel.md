## 2024-05-23 - Outdated Device Regex
**Vulnerability:** The regex patterns for detecting dangerous disk operations (`mkfs`, `dd`, `>`) only matched legacy `/dev/sd[a-z]` devices, completely missing modern NVMe (`/dev/nvme0n1`) and MMC (`/dev/mmcblk0`) devices.
**Learning:** Security regexes must be updated to reflect modern hardware standards. Hardcoding `sd[a-z]` is a common legacy pattern that leaves newer systems vulnerable.
**Prevention:** Use more inclusive regexes for device names, or better yet, abstract device detection logic to a centralized function that is easier to maintain and update.

## 2025-05-19 - Regex Bypass via Trailing Comments
**Vulnerability:** The regex for detecting `rm -rf /` used `\s*($|[;&|])` to ensure the command ended or was separated. This failed to account for trailing comments (e.g., `rm -rf / # comment`) where the comment character `#` is a valid shell separator/terminator for the command.
**Learning:** When using regex for security checks on shell commands, "whitespace" (`\s`) typically acts as a separator. Any whitespace following a dangerous argument usually means the argument is complete and the danger is present, regardless of what follows (unless it's part of the path, which `/` is not). Relying on explicit terminators like `;`, `|`, `&` without including whitespace or comments (`#`) is brittle.
**Prevention:** Treat whitespace as a terminator for command arguments in security regexes. The pattern `(\s|[;&|]|$)` is more robust than looking for explicit control operators after optional whitespace.
