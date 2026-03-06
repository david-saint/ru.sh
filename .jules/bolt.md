# Performance Learnings

## BufWriter for File I/O
- **Context**: In `crates/ru-cli/src/history.rs`, writing to a file line by line during truncation was unbuffered, causing an I/O syscall overhead per line.
- **Improvement**: Wrapping the output file inside a `BufWriter` batches these writes. Before dropping the writer, explicitly calling `.flush()?` handles any final I/O errors properly.
- **Impact**: In our benchmarks for the rotation of history files, execution time improved by roughly ~11-12% (from 23.26ms down to 20.55ms) due to the reduced number of syscalls.
