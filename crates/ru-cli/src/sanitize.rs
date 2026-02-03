/// Sanitize a string for safe terminal display by removing/escaping
/// control characters and ANSI escape sequences.
///
/// This prevents terminal injection attacks where malicious scripts
/// use escape sequences to hide dangerous commands.
pub fn for_display(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // Skip ANSI escape sequences (ESC [ ... final_byte)
            '\x1b' => {
                if chars.peek() == Some(&'[') {
                    chars.next(); // consume '['
                    // Skip until we hit a letter (final byte of CSI sequence)
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if next.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                // Skip other escape sequences (ESC followed by one char)
                else if chars.peek().is_some() {
                    chars.next();
                }
            }
            // Replace problematic control characters
            '\r' => result.push_str("\\r"),
            '\x08' => result.push_str("\\b"), // backspace
            '\x7f' => result.push_str("\\x7f"), // DEL
            // Allow normal printable chars, newlines, tabs
            c if c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\t' => {
                result.push(c);
            }
            // Escape other control characters
            c if c.is_ascii_control() => {
                result.push_str(&format!("\\x{:02x}", c as u8));
            }
            // Allow non-ASCII (UTF-8) characters
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preserves_normal_script() {
        let input = "echo 'hello world'\nls -la";
        assert_eq!(for_display(input), input);
    }

    #[test]
    fn test_preserves_tabs() {
        let input = "if true; then\n\techo 'yes'\nfi";
        assert_eq!(for_display(input), input);
    }

    #[test]
    fn test_escapes_carriage_return() {
        let input = "safe\rmalicious";
        assert_eq!(for_display(input), "safe\\rmalicious");
    }

    #[test]
    fn test_escapes_backspace() {
        let input = "visible\x08hidden";
        assert_eq!(for_display(input), "visible\\bhidden");
    }

    #[test]
    fn test_strips_ansi_clear_line() {
        let input = "visible\x1b[2Khidden";
        assert_eq!(for_display(input), "visiblehidden");
    }

    #[test]
    fn test_strips_ansi_cursor_movement() {
        let input = "start\x1b[5Aup";
        assert_eq!(for_display(input), "startup");
    }

    #[test]
    fn test_strips_ansi_color_codes() {
        let input = "\x1b[31mred text\x1b[0m";
        assert_eq!(for_display(input), "red text");
    }

    #[test]
    fn test_complex_attack_sequence() {
        // Simulates: show "safe" but hide "rm -rf /"
        let input = "echo 'safe'\r\x1b[2Krm -rf / #";
        let sanitized = for_display(input);
        // Should show both parts, with \r escaped
        assert!(sanitized.contains("echo 'safe'"));
        assert!(sanitized.contains("\\r"));
        assert!(sanitized.contains("rm -rf /"));
    }

    #[test]
    fn test_preserves_utf8() {
        let input = "echo '你好世界'";
        assert_eq!(for_display(input), input);
    }

    #[test]
    fn test_escapes_null_byte() {
        let input = "before\x00after";
        assert_eq!(for_display(input), "before\\x00after");
    }
}
