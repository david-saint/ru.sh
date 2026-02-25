# ru-cli: Tasks for Shipping

## Overview

Current completion: ~90%. All critical tasks complete. Safety system implemented. Remaining work is testing, CI/CD, and polish.

---

## 🔴 Critical (Must Have)

### 1. Implement OpenRouter API Integration
- [x] Create HTTP client with reqwest to call OpenRouter API
- [x] Define request/response structs for the API
- [x] Implement `generate_script()` function
- [x] Add proper prompt engineering for bash script generation
- [x] Handle API responses and extract generated scripts
- [x] Add request timeout handling (30s request, 10s connect)
- [x] Implement retry logic with exponential backoff (max 3 attempts)

### 2. API Error Handling
- [x] Handle network failures gracefully
- [x] Detect and report invalid API keys
- [x] Handle rate limiting (429 responses) with Retry-After header support
- [x] Handle malformed/partial API responses
- [x] Provide actionable error messages to users

### 3. Implement Script Explanation
- [x] Complete the "Explain" option
- [x] Add second API call to explain generated scripts
- [x] Format explanation output for terminal readability

---

## 🟡 Important (Should Have)

### 4. Input Validation & Safety
- [x] Add prompt length validation (3-2000 chars)
- [x] Detect potentially dangerous commands (rm -rf, sudo, curl|bash, fork bomb, etc.)
- [x] Warn users before executing destructive operations (colored risk headers)
- [x] Validate generated script syntax before offering execution (`bash -n`)
- [x] Add `--force` flag for high-risk scripts with `-y`
- [x] Require typing "yes" for High/Critical risk in interactive mode
- [x] Add audit logging to `~/.config/ru.sh/history.jsonl`
- [x] Add API usage tracking with configurable daily/monthly limits

### 5. Expand Configuration
- [x] Add model selection option (`config set model <model>`)
- [x] Add model preset system (fast, standard, quality)
- [x] Add custom model override per preset
- [x] Add configurable explainer model
- [ ] Add temperature/creativity parameter
- [ ] Add shell preference (bash, zsh, fish)
- [ ] Add default behavior preferences (always explain, etc.)

### 6. Logging & Debugging
- [ ] Add `--verbose` flag for debug output
- [ ] Log API requests/responses when debugging
- [ ] Add structured logging with levels (info, debug, trace)

### 7. Integration Tests
- [ ] Add end-to-end tests with mock API server
- [ ] Test actual bash script execution scenarios
- [ ] Test config file corruption recovery
- [ ] Test interactive dialogue flows

### 8. CI/CD Pipeline
- [ ] Set up GitHub Actions for PR checks
- [ ] Add automated testing on push
- [ ] Add clippy and rustfmt checks
- [ ] Set up release automation
- [ ] Add cross-platform build matrix (Linux, macOS, Windows)

---

## 🟢 Nice to Have

### 9. Documentation
- [ ] Add rustdoc comments to all public functions
- [x] Create CONTRIBUTING.md
- [ ] Add CHANGELOG.md
- [ ] Create troubleshooting guide
- [ ] Document API integration architecture

### 10. Distribution
- [ ] Publish to crates.io
- [ ] Create Homebrew formula
- [ ] Add cargo-binstall support
- [ ] Create shell completion scripts (bash, zsh, fish)
- [ ] Add man page

### 11. UX Improvements
- [ ] Add streaming output for long API responses
- [x] Add script history tracking (audit log in `~/.config/ru.sh/history.jsonl`)
- [ ] Add `--edit` flag to modify generated scripts before execution
- [ ] Add syntax highlighting for generated scripts
- [ ] Add progress spinner during API calls

### 12. Advanced Features
- [ ] Add context/conversation mode for multi-turn interactions
- [ ] Support piping input (`echo "list files" | ru`)
- [ ] Add template/preset system for common tasks
- [ ] Integration with ru-web for web-based interface

---

## Current State Summary

| Component | Status |
|-----------|--------|
| CLI argument parsing | ✅ Complete |
| Config system | ✅ Complete |
| User confirmation flow | ✅ Complete |
| Script execution | ✅ Complete |
| API key management | ✅ Complete |
| OpenRouter API calls | ✅ Complete |
| Explanation feature | ✅ Complete |
| Model preset system | ✅ Complete |
| Request timeout/retry | ✅ Complete |
| Input validation | ✅ Complete |
| Safety/risk detection | ✅ Complete |
| Audit logging | ✅ Complete |
| Usage tracking | ✅ Complete |
| Integration tests | ❌ Missing |
| CI/CD | ❌ Missing |
| Documentation | ⚠️ Minimal |

---

## Suggested Priority Order

1. ~~OpenRouter API Integration (#1, #2)~~ ✅ Done
2. ~~Script Explanation (#3)~~ ✅ Done
3. ~~Request timeout/retry hardening~~ ✅ Done
4. ~~Input Validation & Safety (#4)~~ ✅ Done
5. CI/CD Pipeline (#8)
6. Integration Tests (#7)
7. Everything else
