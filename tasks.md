# ru-cli: Tasks for Shipping

## Overview

Current completion: ~30%. The CLI skeleton is solid but the core API integration is stubbed.

---

## 🔴 Critical (Must Have)

### 1. Implement OpenRouter API Integration
- [ ] Create HTTP client with reqwest to call OpenRouter API
- [ ] Define request/response structs for the API
- [ ] Implement `generate_script()` function (currently stubbed at `main.rs:222`)
- [ ] Add proper prompt engineering for bash script generation
- [ ] Handle API responses and extract generated scripts
- [ ] Add request timeout handling
- [ ] Implement retry logic with exponential backoff

### 2. API Error Handling
- [ ] Handle network failures gracefully
- [ ] Detect and report invalid API keys
- [ ] Handle rate limiting (429 responses)
- [ ] Handle malformed/partial API responses
- [ ] Provide actionable error messages to users

### 3. Implement Script Explanation
- [ ] Complete the "Explain" option (marked "coming soon" at `main.rs:175`)
- [ ] Add second API call to explain generated scripts
- [ ] Format explanation output for terminal readability

---

## 🟡 Important (Should Have)

### 4. Input Validation & Safety
- [ ] Add prompt length validation
- [ ] Detect potentially dangerous commands (rm -rf, sudo, etc.)
- [ ] Warn users before executing destructive operations
- [ ] Validate generated script syntax before offering execution

### 5. Expand Configuration
- [ ] Add model selection option (`config set model <model>`)
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
- [ ] Create CONTRIBUTING.md
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
- [ ] Add script history tracking
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
| OpenRouter API calls | ❌ Stubbed |
| Explanation feature | ❌ Not implemented |
| Integration tests | ❌ Missing |
| CI/CD | ❌ Missing |
| Documentation | ⚠️ Minimal |

---

## Suggested Priority Order

1. OpenRouter API Integration (#1, #2)
2. Script Explanation (#3)
3. CI/CD Pipeline (#8)
4. Integration Tests (#7)
5. Input Validation (#4)
6. Everything else
