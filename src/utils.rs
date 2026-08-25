//! Wire-level helpers shared by the command serialisers and the
//! response parser.
//!
//! ManageSieve borrows its three data types from ACAP: atoms, numbers
//! and strings, a string being either quoted or a length-prefixed
//! literal ([RFC 5804 section 1.2]). Reading a response therefore means
//! reading a line, then possibly a counted run of octets, then the rest
//! of that same line, which is what [`scan_line`] does. Writing a
//! command means quoting a script name or framing a script body, which
//! is what [`quote`] and [`literal`] do.
//!
//! The module is private: a caller passes plain strings and byte slices
//! and reads back the parsed types of [`crate::rfc5804::response`].
//!
//! [RFC 5804 section 1.2]: https://www.rfc-editor.org/rfc/rfc5804#section-1.2

use core::str;

use alloc::{format, string::String, vec::Vec};

use crate::rfc5804::response::{MAX_LITERAL, ManagesieveResponseParseError};

/// One lexed item of a response line.
///
/// Parentheses are lexed apart from atoms because they delimit the
/// response code, and [RFC 5804 section 4] lists them among the
/// ATOM-SPECIALS an atom cannot contain.
///
/// [RFC 5804 section 4]: https://www.rfc-editor.org/rfc/rfc5804#section-4
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Token {
    /// A quoted or literal string, unescaped and unframed.
    String(Vec<u8>),
    /// A bare atom, such as a status word or a response code name.
    Atom(Vec<u8>),
    /// The opening parenthesis of a response code.
    Open,
    /// The closing parenthesis of a response code.
    Close,
}

/// Reads one logical response line from the front of `buf`.
///
/// A logical line spans as many physical lines as it has literals, each
/// literal marker consuming the counted octets that follow the CRLF and
/// the line resuming right after them. Returns [`None`] while the line
/// is still incomplete, and the tokens plus the number of bytes they
/// consumed once it is.
pub(crate) fn scan_line(
    buf: &[u8],
) -> Result<Option<(Vec<Token>, usize)>, ManagesieveResponseParseError> {
    let mut tokens = Vec::new();
    let mut index = 0;

    loop {
        let Some(offset) = buf[index..].iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };

        let eol = index + offset;
        let mut end = eol;

        if end > index && buf[end - 1] == b'\r' {
            end -= 1;
        }

        let (mut lexed, marker) = lex(&buf[index..end])?;
        tokens.append(&mut lexed);

        let Some(size) = marker else {
            return Ok(Some((tokens, eol + 1)));
        };

        let start = eol + 1;
        let Some(stop) = start.checked_add(size) else {
            return Err(ManagesieveResponseParseError::LiteralTooLarge(size));
        };

        if buf.len() < stop {
            return Ok(None);
        }

        tokens.push(Token::String(buf[start..stop].to_vec()));
        index = stop;
    }
}

/// Lexes one physical segment, CRLF already stripped.
///
/// Returns the tokens it holds and, when the segment ends on a literal
/// marker, the octet count that marker announces.
fn lex(segment: &[u8]) -> Result<(Vec<Token>, Option<usize>), ManagesieveResponseParseError> {
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < segment.len() {
        if segment[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }

        match segment[index] {
            b'"' => {
                let (string, next) = lex_quoted(segment, index)?;
                tokens.push(Token::String(string));
                index = next;
            }
            b'{' => {
                let size = lex_literal_marker(&segment[index..])?;
                return Ok((tokens, Some(size)));
            }
            b'(' => {
                tokens.push(Token::Open);
                index += 1;
            }
            b')' => {
                tokens.push(Token::Close);
                index += 1;
            }
            _ => {
                let start = index;

                while index < segment.len() && !is_atom_special(segment[index]) {
                    index += 1;
                }

                if index == start {
                    let byte = segment[index];
                    return Err(ManagesieveResponseParseError::UnexpectedByte(byte));
                }

                tokens.push(Token::Atom(segment[start..index].to_vec()));
            }
        }
    }

    Ok((tokens, None))
}

/// Lexes a quoted string starting at the opening double quote.
///
/// A backslash escapes the two QUOTED-SPECIALS and nothing else, so
/// `\n` inside a quoted string is a literal `n` rather than a newline.
fn lex_quoted(
    segment: &[u8],
    open: usize,
) -> Result<(Vec<u8>, usize), ManagesieveResponseParseError> {
    let mut string = Vec::new();
    let mut index = open + 1;

    while index < segment.len() {
        match segment[index] {
            b'"' => return Ok((string, index + 1)),
            b'\\' => {
                let Some(byte) = segment.get(index + 1).copied() else {
                    return Err(ManagesieveResponseParseError::UnterminatedQuoted);
                };

                if byte != b'"' && byte != b'\\' {
                    return Err(ManagesieveResponseParseError::InvalidEscape(byte));
                }

                string.push(byte);
                index += 2;
            }
            byte => {
                string.push(byte);
                index += 1;
            }
        }
    }

    Err(ManagesieveResponseParseError::UnterminatedQuoted)
}

/// Reads a `{size}` or `{size+}` marker occupying the rest of a
/// segment.
///
/// The non-synchronising `+` form is client-to-server only, but it is
/// accepted here too: a server sending one is malformed in a way that
/// costs nothing to read.
fn lex_literal_marker(marker: &[u8]) -> Result<usize, ManagesieveResponseParseError> {
    let Some(digits) = marker
        .strip_prefix(b"{")
        .and_then(|rest| rest.strip_suffix(b"}"))
    else {
        return Err(ManagesieveResponseParseError::InvalidLiteralMarker);
    };

    let digits = digits.strip_suffix(b"+").unwrap_or(digits);

    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(ManagesieveResponseParseError::InvalidLiteralMarker);
    }

    let size = str::from_utf8(digits)
        .ok()
        .and_then(|digits| digits.parse::<u32>().ok())
        .ok_or(ManagesieveResponseParseError::InvalidLiteralMarker)?;

    let size = size as usize;

    if size > MAX_LITERAL {
        return Err(ManagesieveResponseParseError::LiteralTooLarge(size));
    }

    Ok(size)
}

/// Whether `byte` is one of the ATOM-SPECIALS an atom cannot contain.
fn is_atom_special(byte: u8) -> bool {
    matches!(byte, b'(' | b')' | b'{' | b' ' | b'"' | b'\\') || byte.is_ascii_control()
}

/// Renders `value` as a quoted string.
///
/// Returns [`None`] when the value cannot travel quoted, meaning it
/// holds a control character or exceeds the 1024 octets [RFC 5804
/// section 4] allows between the quotes. The caller falls back to
/// [`literal`], which carries any octet sequence at all.
///
/// [RFC 5804 section 4]: https://www.rfc-editor.org/rfc/rfc5804#section-4
pub(crate) fn quote(value: &[u8]) -> Option<Vec<u8>> {
    let escapes = value
        .iter()
        .filter(|byte| is_quoted_special(**byte))
        .count();

    if value.len() + escapes > QUOTED_MAX || value.iter().copied().any(|b| b.is_ascii_control()) {
        return None;
    }

    let mut quoted = Vec::with_capacity(value.len() + escapes + 2);
    quoted.push(b'"');

    for byte in value.iter().copied() {
        if is_quoted_special(byte) {
            quoted.push(b'\\');
        }

        quoted.push(byte);
    }

    quoted.push(b'"');
    Some(quoted)
}

/// Renders `value` as a non-synchronising literal, marker and octets.
///
/// The `+` form is the only one a client may send, and it is what lets
/// a whole command travel in a single write rather than waiting for a
/// continuation the protocol does not have.
pub(crate) fn literal(value: &[u8]) -> Vec<u8> {
    let marker = format!("{{{}+}}\r\n", value.len());
    let mut bytes = Vec::with_capacity(marker.len() + value.len());

    bytes.extend_from_slice(marker.as_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// Renders `value` as a string, quoted when it fits and literal
/// otherwise.
pub(crate) fn string(value: &[u8]) -> Vec<u8> {
    quote(value).unwrap_or_else(|| literal(value))
}

/// Renders bytes for a trace log, escaping what a terminal would eat.
pub(crate) fn escape_byte_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .map(|byte| match byte {
            b'\r' => String::from("\\r"),
            b'\n' => String::from("\\n"),
            b'\t' => String::from("\\t"),
            byte if byte.is_ascii_graphic() || byte == b' ' => String::from(byte as char),
            byte => format!("\\x{byte:02x}"),
        })
        .collect()
}

/// Whether `byte` is one of the two QUOTED-SPECIALS a quoted string
/// escapes.
fn is_quoted_special(byte: u8) -> bool {
    byte == b'"' || byte == b'\\'
}

/// The octets a quoted string may hold between its double quotes.
const QUOTED_MAX: usize = 1024;

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use crate::{
        rfc5804::response::{MAX_LITERAL, ManagesieveResponseParseError},
        utils::{QUOTED_MAX, *},
    };

    #[test]
    fn scans_a_line_of_quoted_strings() {
        let buf = b"\"IMPLEMENTATION\" \"Example1 ManageSieved v001\"\r\n";
        let (tokens, consumed) = scan_line(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(
            tokens,
            vec![
                Token::String(b"IMPLEMENTATION".to_vec()),
                Token::String(b"Example1 ManageSieved v001".to_vec()),
            ]
        );
    }

    #[test]
    fn resumes_a_line_after_a_literal() {
        // NOTE: RFC 5804 section 2.7 lists a literal script name
        // followed by the ACTIVE atom, which is the case that makes a
        // logical line span two physical ones.
        let buf = b"{15}\r\nvacation script ACTIVE\r\n";
        let (tokens, consumed) = scan_line(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(
            tokens,
            vec![
                Token::String(b"vacation script".to_vec()),
                Token::Atom(b"ACTIVE".to_vec()),
            ]
        );
    }

    #[test]
    fn scans_a_response_code_holding_a_literal() {
        // NOTE: the TAG response code of RFC 5804 section 2.13, whose
        // string may be a literal sitting between the parentheses.
        let buf = b"OK (TAG {16}\r\nSTARTTLS-SYNC-42) \"Done\"\r\n";
        let (tokens, consumed) = scan_line(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(
            tokens,
            vec![
                Token::Atom(b"OK".to_vec()),
                Token::Open,
                Token::Atom(b"TAG".to_vec()),
                Token::String(b"STARTTLS-SYNC-42".to_vec()),
                Token::Close,
                Token::String(b"Done".to_vec()),
            ]
        );
    }

    #[test]
    fn keeps_the_newlines_a_literal_carries() {
        let script = b"require [\"fileinto\"];\r\n";
        let buf = b"{23}\r\nrequire [\"fileinto\"];\r\n\r\n";
        let (tokens, consumed) = scan_line(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(tokens, vec![Token::String(script.to_vec())]);
    }

    #[test]
    fn reports_an_incomplete_line_and_an_incomplete_literal() {
        assert_eq!(scan_line(b"\"IMPLEMENTATION\"").unwrap(), None);
        assert_eq!(scan_line(b"{15}\r\nvacation").unwrap(), None);
    }

    #[test]
    fn unescapes_a_quoted_string_and_refuses_a_broken_one() {
        let buf = b"\"vac\\\\ation\" \"say \\\"hi\\\"\"\r\n";
        let (tokens, _) = scan_line(buf).unwrap().unwrap();

        assert_eq!(
            tokens,
            vec![
                Token::String(b"vac\\ation".to_vec()),
                Token::String(b"say \"hi\"".to_vec()),
            ]
        );

        let err = scan_line(b"\"unterminated\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::UnterminatedQuoted
        ));

        let err = scan_line(b"\"bad \\n escape\"\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::InvalidEscape(b'n')
        ));
    }

    #[test]
    fn refuses_a_malformed_or_oversized_literal_marker() {
        let err = scan_line(b"{abc}\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::InvalidLiteralMarker
        ));

        let err = scan_line(b"{12\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::InvalidLiteralMarker
        ));

        let marker = format!("{{{}}}\r\n", MAX_LITERAL + 1);
        let err = scan_line(marker.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::LiteralTooLarge(_)
        ));
    }

    #[test]
    fn quotes_what_fits_and_falls_back_to_a_literal() {
        assert_eq!(string(b"main"), b"\"main\"");
        assert_eq!(string(b"vac\"ation"), b"\"vac\\\"ation\"");
        assert_eq!(string(b"two\nlines"), b"{9+}\r\ntwo\nlines");

        let long = vec![b'x'; QUOTED_MAX + 1];
        assert!(quote(&long).is_none());
        assert!(string(&long).starts_with(b"{1025+}\r\n"));
    }

    #[test]
    fn escapes_bytes_for_a_trace_log() {
        assert_eq!(escape_byte_string(b"OK\r\n\x00"), "OK\\r\\n\\x00");
    }
}
