use std::borrow::Cow;

fn is_invisible_or_bidi_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // Soft hyphen
            | '\u{034F}' // Combining grapheme joiner
            | '\u{061C}' // Arabic Letter Mark
            | '\u{200B}'..='\u{200F}' // Zero-width + LRM/RLM
            | '\u{202A}'..='\u{202E}' // BiDi embedding/override controls
            | '\u{2060}'..='\u{2064}' // Word joiner + invisible operators
            | '\u{2066}'..='\u{2069}' // BiDi isolate controls
            | '\u{FEFF}' // Zero-width no-break space (BOM)
    )
}

/// Sanitizes a string for safe terminal display.
///
/// This function removes or escapes control characters and ANSI escape sequences
/// to prevent terminal injection attacks, where malicious scripts might use
/// escape sequences to hide dangerous commands from the user's view.
///
/// # Arguments
///
/// * `input` - The string to sanitize.
///
/// # Returns
///
/// A `Cow<'_, str>` containing the sanitized version of the input.
pub fn for_display(input: &str) -> Cow<'_, str> {
    // Fast path: find the first character that requires escaping.
    // By using `find`, we avoid calling `.all()` which checks the whole string
    // before we even start building the result string.
    let bad_idx = input.find(|c: char| {
        (c.is_ascii_control() && c != '\n' && c != '\t') || is_invisible_or_bidi_char(c)
    });

    let Some(bad_idx) = bad_idx else {
        return Cow::Borrowed(input);
    };

    // We allocate with some extra capacity because escape sequences will increase the length.
    let mut result = String::with_capacity(input.len() + 16);

    // Copy the safe prefix exactly as is
    result.push_str(&input[..bad_idx]);

    // Process the remaining characters
    let mut chars = input[bad_idx..].chars().peekable();

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
            '\x08' => result.push_str("\\b"),   // backspace
            '\x7f' => result.push_str("\\x7f"), // DEL
            // Render invisible/bidi Unicode controls visibly to prevent spoofing
            c if is_invisible_or_bidi_char(c) => {
                use std::fmt::Write;
                let _ = write!(result, "\\u{{{:04X}}}", c as u32);
            }
            // Allow normal printable chars, newlines, tabs
            c if c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\t' => {
                result.push(c);
            }
            // Escape other control characters
            c if c.is_ascii_control() => {
                use std::fmt::Write;
                let _ = write!(result, "\\x{:02x}", c as u8);
            }
            // Allow non-ASCII (UTF-8) characters
            c => result.push(c),
        }
    }
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preserves_normal_script() {
        let input = "echo 'hello world'\nls -la";
        assert_eq!(for_display(input), input);
        // Verify it returns Borrowed
        assert!(matches!(for_display(input), Cow::Borrowed(_)));
    }

    #[test]
    fn test_preserves_tabs() {
        let input = "if true; then\n\techo 'yes'\nfi";
        assert_eq!(for_display(input), input);
        assert!(matches!(for_display(input), Cow::Borrowed(_)));
    }

    #[test]
    fn test_escapes_carriage_return() {
        let input = "safe\rmalicious";
        assert_eq!(for_display(input), "safe\\rmalicious");
        assert!(matches!(for_display(input), Cow::Owned(_)));
    }

    #[test]
    fn test_escapes_backspace() {
        let input = "visible\x08hidden";
        assert_eq!(for_display(input), "visible\\bhidden");
        assert!(matches!(for_display(input), Cow::Owned(_)));
    }

    #[test]
    fn test_strips_ansi_clear_line() {
        let input = "visible\x1b[2Khidden";
        assert_eq!(for_display(input), "visiblehidden");
        assert!(matches!(for_display(input), Cow::Owned(_)));
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
        assert!(matches!(for_display(input), Cow::Borrowed(_)));
    }

    #[test]
    fn test_escapes_null_byte() {
        let input = "before\x00after";
        assert_eq!(for_display(input), "before\\x00after");
    }

    #[test]
    fn test_escapes_bidi_override() {
        let input = "echo safe \u{202E}rm -rf /";
        assert_eq!(for_display(input), "echo safe \\u{202E}rm -rf /");
    }

    #[test]
    fn test_escapes_zero_width_chars() {
        let input = "safe\u{200B}text";
        assert_eq!(for_display(input), "safe\\u{200B}text");
    }
}
