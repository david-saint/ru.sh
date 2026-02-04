## 2024-05-23 - Outdated Device Regex
**Vulnerability:** The regex patterns for detecting dangerous disk operations (`mkfs`, `dd`, `>`) only matched legacy `/dev/sd[a-z]` devices, completely missing modern NVMe (`/dev/nvme0n1`) and MMC (`/dev/mmcblk0`) devices.
**Learning:** Security regexes must be updated to reflect modern hardware standards. Hardcoding `sd[a-z]` is a common legacy pattern that leaves newer systems vulnerable.
**Prevention:** Use more inclusive regexes for device names, or better yet, abstract device detection logic to a centralized function that is easier to maintain and update.
