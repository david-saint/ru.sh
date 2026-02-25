# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.13] - 2026-02-25

### Added
- Performance critical learnings journaling in `.jules/bolt.md`.

### Changed
- Performance optimizations for API response processing.
- Optimized `analyze_script` in `ru-cli` to reduce subprocess overhead.
- Improved `rotate_history` in `history.rs` to use zero-allocation-churn ring buffer.

### Fixed
- General code cleanup and performance followup.

## [0.1.12] - 2026-02-11

### Changed
- Bumped workspace version to 0.1.12.

## [0.1.11] - 2026-02-09

### Fixed
- Urgent safety hardening for dangerous command detection.

## [0.1.10] - 2026-02-08

### Changed
- Bumped workspace version to 0.1.10.

## [0.1.9] - 2026-02-08

### Changed
- Major performance and code quality improvements across the workspace.

## [0.1.8] - 2026-02-06

### Added
- Auto-update feature for `ru-cli`.

## [0.1.7] - 2026-02-06

### Changed
- Added `workflow_dispatch` to release workflow.

## [0.1.6] - 2026-02-05

### Added
- Added favicon to `ru-web`.

### Fixed
- Fixed CLI safety tests.

## [0.1.5] - 2026-02-04

### Changed
- Performed security audit for `ru-cli`.

## [0.1.4] - 2026-02-03

### Added
- Added duration tracking to history and execution output.

## [0.1.3] - 2026-02-03

### Changed
- Switched to `rustls` for improved cross-compilation support.

## [0.1.2] - 2026-02-03

### Fixed
- Addressed security vulnerabilities and updated CI.

## [0.1.1] - 2026-02-03

### Fixed
- Addressed security vulnerabilities.

## [0.1.0] - 2026-02-03

### Added
- Initial release of **ru.sh**.
- Natural Language Interface for generating bash scripts.
- Safety & Risk Analysis system.
- Multi-Shell Support (Bash, Zsh, Fish, PowerShell, Cmd).
- Script Explanation feature via OpenRouter API.
- Prompt Injection Protection.
- Execution History logging in JSONL format.
- Model Presets (fast, standard, quality).
- Configuration management via CLI.
- API Usage Tracking and limits.
