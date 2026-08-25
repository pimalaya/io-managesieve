//! The response half of the protocol: data lines, the completion line
//! ending them, and the response code a completion may carry.
//!
//! Every command answers the same way ([RFC 5804 section 1.1]): zero or
//! more data lines whose shape belongs to that command, then one
//! completion line saying OK, NO or BYE. So the framing is parsed once,
//! here, and each command coroutine only interprets the data lines it
//! asked for.
//!
//! A response code is the machine-readable half of a completion ([RFC
//! 5804 section 1.3]). It is what tells a caller that a script name was
//! free rather than taken, that a quota was reached rather than a
//! syntax error made, or that a stored script compiled with warnings.
//! Clients must tolerate codes they do not know, so an unmodelled one
//! keeps its name in [`ManagesieveResponseCode::Other`] rather than
//! failing the parse.
//!
//! [RFC 5804 section 1.1]: https://www.rfc-editor.org/rfc/rfc5804#section-1.1
//! [RFC 5804 section 1.3]: https://www.rfc-editor.org/rfc/rfc5804#section-1.3

use core::fmt;

use alloc::{string::String, vec::Vec};

use thiserror::Error;

use crate::utils::{Token, scan_line};

/// The largest literal this crate reads before giving up.
///
/// A literal announces its own length, so a hostile or corrupted
/// marker would otherwise ask for an allocation of any size at all.
/// Sieve scripts live under a server quota measured in kilobytes, so
/// the ceiling is far above anything legitimate and exists only to keep
/// the failure a parse error rather than an abort.
pub const MAX_LITERAL: usize = 8 * 1024 * 1024;

/// Failure causes while parsing a ManageSieve response.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ManagesieveResponseParseError {
    /// A logical line carried no token at all.
    #[error("Parse ManageSieve response error: empty response line")]
    EmptyLine,
    /// A byte turned up where no token can start.
    #[error("Parse ManageSieve response error: unexpected byte {0:#04x}")]
    UnexpectedByte(u8),
    /// A quoted string ran to the end of its line without closing.
    #[error("Parse ManageSieve response error: unterminated quoted string")]
    UnterminatedQuoted,
    /// A backslash escaped something other than the two
    /// QUOTED-SPECIALS.
    #[error("Parse ManageSieve response error: invalid escape byte {:#04x}", .0)]
    InvalidEscape(u8),
    /// A literal marker was not `{size}` or `{size+}`.
    #[error("Parse ManageSieve response error: invalid literal marker")]
    InvalidLiteralMarker,
    /// A literal announced more octets than this crate reads.
    #[error("Parse ManageSieve response error: literal of {0} bytes exceeds {MAX_LITERAL}")]
    LiteralTooLarge(usize),
    /// A completion line opened with something other than OK, NO or
    /// BYE.
    #[error("Parse ManageSieve response error: unknown completion status `{0}`")]
    UnknownStatus(String),
    /// A response code opened but never closed.
    #[error("Parse ManageSieve response error: unterminated response code")]
    UnterminatedResponseCode,
    /// A response code held no name.
    #[error("Parse ManageSieve response error: empty response code")]
    EmptyResponseCode,
}

/// The completion status ending a ManageSieve response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagesieveStatus {
    /// The command succeeded.
    Ok,
    /// The command failed and the session stays open.
    No,
    /// The server is closing the connection, whether or not the command
    /// succeeded.
    Bye,
}

impl ManagesieveStatus {
    /// The status word as it travels on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::No => "NO",
            Self::Bye => "BYE",
        }
    }
}

impl fmt::Display for ManagesieveStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which quota a QUOTA response code was refined to.
///
/// The code is hierarchical, so a server naming no detail means the
/// quota as a whole and a server naming one this crate does not know is
/// read as the same.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagesieveQuota {
    /// `QUOTA/MAXSCRIPTS`: the number of scripts the user may store.
    MaxScripts,
    /// `QUOTA/MAXSIZE`: the size one script may reach.
    MaxSize,
}

/// The machine-readable code a completion line may carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagesieveResponseCode {
    /// `AUTH-TOO-WEAK`: site policy forbids the mechanism for this
    /// identity.
    AuthTooWeak,
    /// `ENCRYPT-NEEDED`: site policy wants a strong encryption layer
    /// first.
    EncryptNeeded,
    /// `QUOTA`: the command would cross a quota, or, on an OK, came
    /// close to one.
    Quota(Option<ManagesieveQuota>),
    /// `REFERRAL`: the user's scripts live on the named `sieve://`
    /// server.
    Referral(String),
    /// `SASL`: the final server response data of an authentication
    /// exchange, still base64-encoded.
    ///
    /// Transport encoding belongs to the exchange that reads it, so the
    /// bytes are carried verbatim and decoded by
    /// [`crate::rfc5804::authenticate`].
    Sasl(Vec<u8>),
    /// `TRANSITION-NEEDED`: the account exists but has no credentials
    /// for the mechanism.
    TransitionNeeded,
    /// `TRYLATER`: a temporary server failure, the command may be
    /// repeated.
    TryLater,
    /// `ACTIVE`: the command is not allowed on the active script.
    Active,
    /// `NONEXISTENT`: the named script does not exist.
    Nonexistent,
    /// `ALREADYEXISTS`: the named script already exists.
    AlreadyExists,
    /// `WARNINGS`: the script is valid but the text carries warnings
    /// worth showing.
    Warnings,
    /// `TAG`: the string a NOOP asked the server to echo back.
    Tag(String),
    /// A response code this crate does not model, by name.
    ///
    /// Clients must tolerate unknown codes, so the name survives and
    /// its arguments do not: acting on them would mean understanding
    /// them, and the human-readable text is what a caller shows
    /// instead.
    Other(String),
}

impl fmt::Display for ManagesieveResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthTooWeak => f.write_str("AUTH-TOO-WEAK"),
            Self::EncryptNeeded => f.write_str("ENCRYPT-NEEDED"),
            Self::Quota(None) => f.write_str("QUOTA"),
            Self::Quota(Some(ManagesieveQuota::MaxScripts)) => f.write_str("QUOTA/MAXSCRIPTS"),
            Self::Quota(Some(ManagesieveQuota::MaxSize)) => f.write_str("QUOTA/MAXSIZE"),
            Self::Referral(url) => write!(f, "REFERRAL {url}"),
            Self::Sasl(_) => f.write_str("SASL"),
            Self::TransitionNeeded => f.write_str("TRANSITION-NEEDED"),
            Self::TryLater => f.write_str("TRYLATER"),
            Self::Active => f.write_str("ACTIVE"),
            Self::Nonexistent => f.write_str("NONEXISTENT"),
            Self::AlreadyExists => f.write_str("ALREADYEXISTS"),
            Self::Warnings => f.write_str("WARNINGS"),
            Self::Tag(tag) => write!(f, "TAG {tag}"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

/// One token of a response data line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagesieveToken {
    /// A quoted or literal string, unescaped and unframed.
    String(Vec<u8>),
    /// A bare atom, the ACTIVE marker of LISTSCRIPTS being the only one
    /// a data line carries.
    Atom(String),
}

impl fmt::Display for ManagesieveToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(string) => write!(f, "{:?}", String::from_utf8_lossy(string)),
            Self::Atom(atom) => f.write_str(atom),
        }
    }
}

/// One data line of a response, split into its tokens.
///
/// What the tokens mean belongs to the command that asked for them: a
/// capability name and its value, a script name and its ACTIVE marker,
/// a script body or an authentication challenge on their own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveDataLine {
    /// The tokens the line carries, in wire order.
    pub tokens: Vec<ManagesieveToken>,
}

impl ManagesieveDataLine {
    /// The string token sitting at `index`, when the line has one
    /// there.
    pub fn string(&self, index: usize) -> Option<&[u8]> {
        match self.tokens.get(index)? {
            ManagesieveToken::String(string) => Some(string),
            ManagesieveToken::Atom(_) => None,
        }
    }

    /// Whether the line carries `atom`, compared case-insensitively as
    /// the specification asks.
    pub fn has_atom(&self, atom: &str) -> bool {
        self.tokens.iter().any(|token| match token {
            ManagesieveToken::Atom(found) => found.eq_ignore_ascii_case(atom),
            ManagesieveToken::String(_) => false,
        })
    }
}

impl fmt::Display for ManagesieveDataLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, token) in self.tokens.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }

            write!(f, "{token}")?;
        }

        Ok(())
    }
}

/// The completion line ending a response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveCompletion {
    /// Whether the command succeeded, failed, or ended the session.
    pub status: ManagesieveStatus,
    /// The response code, when the server sent one.
    pub code: Option<ManagesieveResponseCode>,
    /// The human-readable text, when the server sent one, decoded from
    /// UTF-8 with invalid sequences replaced.
    pub text: Option<String>,
}

impl ManagesieveCompletion {
    /// The warning text a server attached to an accepted script.
    ///
    /// PUTSCRIPT and CHECKSCRIPT answer OK with the WARNINGS code when
    /// a script is valid but suspicious, and the text names the lines
    /// worth looking at. Answers [`None`] when there is nothing to
    /// show.
    pub fn warnings(&self) -> Option<&str> {
        match self.code {
            Some(ManagesieveResponseCode::Warnings) => self.text.as_deref(),
            _ => None,
        }
    }
}

impl fmt::Display for ManagesieveCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status)?;

        if let Some(code) = &self.code {
            write!(f, " ({code})")?;
        }

        if let Some(text) = &self.text {
            write!(f, " {text}")?;
        }

        Ok(())
    }
}

/// One logical line of a response.
///
/// A logical line spans as many physical ones as it has literals, so
/// what a caller reads a line at a time is this rather than a CRLF-
/// delimited chunk. Only the authentication exchange needs the
/// distinction: every other command reads whole responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagesieveLine {
    /// A data line preceding the completion.
    Data(ManagesieveDataLine),
    /// The completion line ending the response.
    Completion(ManagesieveCompletion),
}

impl ManagesieveLine {
    /// Parses one logical line from the front of `buf`.
    ///
    /// Returns [`None`] while the line is still incomplete, and the
    /// line together with the number of bytes it consumed once it is.
    pub fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>, ManagesieveResponseParseError> {
        let Some((tokens, consumed)) = scan_line(buf)? else {
            return Ok(None);
        };

        // NOTE: every data line the grammar defines opens on a string,
        // and every completion line opens on one of three atoms, so the
        // first token alone tells the two apart.
        let line = match tokens.first() {
            Some(Token::String(_)) => Self::Data(parse_data(tokens)?),
            _ => Self::Completion(parse_completion(&tokens)?),
        };

        Ok(Some((line, consumed)))
    }
}

/// A complete response: its data lines and the completion ending them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagesieveResponse {
    /// The data lines the command produced, in wire order.
    pub data: Vec<ManagesieveDataLine>,
    /// The completion line ending the response.
    pub completion: ManagesieveCompletion,
}

impl ManagesieveResponse {
    /// Parses one complete response from the front of `buf`.
    ///
    /// Returns [`None`] while the response is still incomplete, and the
    /// response together with the number of bytes it consumed once it
    /// is. Scanning for the end and reading the tokens are the same
    /// walk over the literals, so they are one pass rather than a
    /// completeness check followed by a parse.
    pub fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>, ManagesieveResponseParseError> {
        let mut data = Vec::new();
        let mut consumed = 0;

        loop {
            let Some((line, read)) = ManagesieveLine::parse(&buf[consumed..])? else {
                return Ok(None);
            };

            consumed += read;

            match line {
                ManagesieveLine::Data(line) => data.push(line),
                ManagesieveLine::Completion(completion) => {
                    let response = Self { data, completion };
                    return Ok(Some((response, consumed)));
                }
            }
        }
    }

    /// Splits the response on its status: itself on OK, its completion
    /// on NO or BYE.
    ///
    /// An OK response is returned whole rather than unwrapped, since
    /// its own completion carries what a caller still needs: the
    /// WARNINGS code of a stored script, the TAG a NOOP echoed, the
    /// final SASL data of an authentication exchange.
    pub fn into_result(self) -> Result<Self, ManagesieveCompletion> {
        match self.completion.status {
            ManagesieveStatus::Ok => Ok(self),
            _ => Err(self.completion),
        }
    }
}

impl fmt::Display for ManagesieveResponse {
    /// Renders the response roughly as the server sent it, one line per
    /// line, for the diagnostic commands a caller exposes.
    ///
    /// A literal comes back quoted rather than length-prefixed, since
    /// this is for reading rather than for replaying.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.data {
            writeln!(f, "{line}")?;
        }

        write!(f, "{}", self.completion)
    }
}

/// Turns the tokens of a data line into their public shape.
fn parse_data(tokens: Vec<Token>) -> Result<ManagesieveDataLine, ManagesieveResponseParseError> {
    let tokens = tokens
        .into_iter()
        .map(|token| match token {
            Token::String(string) => Ok(ManagesieveToken::String(string)),
            Token::Atom(atom) => Ok(ManagesieveToken::Atom(text(&atom))),
            Token::Open => Err(ManagesieveResponseParseError::UnexpectedByte(b'(')),
            Token::Close => Err(ManagesieveResponseParseError::UnexpectedByte(b')')),
        })
        .collect::<Result<_, _>>()?;

    Ok(ManagesieveDataLine { tokens })
}

/// Reads a completion line: the status, its optional response code and
/// its optional human-readable text.
fn parse_completion(
    tokens: &[Token],
) -> Result<ManagesieveCompletion, ManagesieveResponseParseError> {
    let atom = match tokens.first() {
        Some(Token::Atom(atom)) => atom,
        Some(_) => return Err(ManagesieveResponseParseError::UnexpectedByte(b'(')),
        None => return Err(ManagesieveResponseParseError::EmptyLine),
    };

    let status = if atom.eq_ignore_ascii_case(b"OK") {
        ManagesieveStatus::Ok
    } else if atom.eq_ignore_ascii_case(b"NO") {
        ManagesieveStatus::No
    } else if atom.eq_ignore_ascii_case(b"BYE") {
        ManagesieveStatus::Bye
    } else {
        return Err(ManagesieveResponseParseError::UnknownStatus(text(atom)));
    };

    let (code, rest) = match tokens.get(1) {
        Some(Token::Open) => {
            let end = tokens[2..]
                .iter()
                .position(|token| *token == Token::Close)
                .ok_or(ManagesieveResponseParseError::UnterminatedResponseCode)?;

            (Some(parse_code(&tokens[2..2 + end])?), &tokens[3 + end..])
        }
        _ => (None, &tokens[1.min(tokens.len())..]),
    };

    let text = match rest.first() {
        Some(Token::String(string)) => Some(text(string)),
        _ => None,
    };

    Ok(ManagesieveCompletion { status, code, text })
}

/// Reads the tokens sitting between the parentheses of a response code.
fn parse_code(tokens: &[Token]) -> Result<ManagesieveResponseCode, ManagesieveResponseParseError> {
    let Some(Token::Atom(name)) = tokens.first() else {
        return Err(ManagesieveResponseParseError::EmptyResponseCode);
    };

    let argument = || match tokens.get(1) {
        Some(Token::String(string)) => string.clone(),
        _ => Vec::new(),
    };

    // NOTE: the code name is a slash-separated hierarchy, and a client
    // reading a detail it does not know reads it as the level above.
    let (head, detail) = match name.iter().position(|byte| *byte == b'/') {
        Some(slash) => (&name[..slash], Some(&name[slash + 1..])),
        None => (&name[..], None),
    };

    let code = if head.eq_ignore_ascii_case(b"AUTH-TOO-WEAK") {
        ManagesieveResponseCode::AuthTooWeak
    } else if head.eq_ignore_ascii_case(b"ENCRYPT-NEEDED") {
        ManagesieveResponseCode::EncryptNeeded
    } else if head.eq_ignore_ascii_case(b"QUOTA") {
        ManagesieveResponseCode::Quota(match detail {
            Some(detail) if detail.eq_ignore_ascii_case(b"MAXSCRIPTS") => {
                Some(ManagesieveQuota::MaxScripts)
            }
            Some(detail) if detail.eq_ignore_ascii_case(b"MAXSIZE") => {
                Some(ManagesieveQuota::MaxSize)
            }
            _ => None,
        })
    } else if head.eq_ignore_ascii_case(b"REFERRAL") {
        ManagesieveResponseCode::Referral(text(&argument()))
    } else if head.eq_ignore_ascii_case(b"SASL") {
        ManagesieveResponseCode::Sasl(argument())
    } else if head.eq_ignore_ascii_case(b"TRANSITION-NEEDED") {
        ManagesieveResponseCode::TransitionNeeded
    } else if head.eq_ignore_ascii_case(b"TRYLATER") {
        ManagesieveResponseCode::TryLater
    } else if head.eq_ignore_ascii_case(b"ACTIVE") {
        ManagesieveResponseCode::Active
    } else if head.eq_ignore_ascii_case(b"NONEXISTENT") {
        ManagesieveResponseCode::Nonexistent
    } else if head.eq_ignore_ascii_case(b"ALREADYEXISTS") {
        ManagesieveResponseCode::AlreadyExists
    } else if head.eq_ignore_ascii_case(b"WARNINGS") {
        ManagesieveResponseCode::Warnings
    } else if head.eq_ignore_ascii_case(b"TAG") {
        ManagesieveResponseCode::Tag(text(&argument()))
    } else {
        ManagesieveResponseCode::Other(text(name))
    };

    Ok(code)
}

/// Decodes server text, which the specification puts in UTF-8, keeping
/// a malformed sequence readable rather than failing the response.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use crate::rfc5804::response::*;

    #[test]
    fn parses_a_capability_response() {
        let buf = b"\"IMPLEMENTATION\" \"Example1\"\r\n\"SIEVE\" \"fileinto vacation\"\r\n\"STARTTLS\"\r\nOK\r\n";
        let (response, consumed) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(response.data.len(), 3);
        assert_eq!(response.data[0].string(0).unwrap(), b"IMPLEMENTATION");
        assert_eq!(response.data[0].string(1).unwrap(), b"Example1");
        assert_eq!(response.data[2].tokens.len(), 1);
        assert_eq!(response.completion.status, ManagesieveStatus::Ok);
        assert_eq!(response.completion.code, None);
        assert_eq!(response.completion.text, None);
    }

    #[test]
    fn parses_a_listscripts_response_mixing_quoted_and_literal_names() {
        let buf = b"\"summer\"\r\n{13}\r\nclever\"script\r\n\"main\" ACTIVE\r\nOK\r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(response.data[1].string(0).unwrap(), b"clever\"script");
        assert!(!response.data[1].has_atom("ACTIVE"));
        assert_eq!(response.data[2].string(0).unwrap(), b"main");
        assert!(response.data[2].has_atom("active"));
    }

    #[test]
    fn parses_a_rejection_and_its_response_code() {
        let buf = b"NO (NONEXISTENT) \"There is no script by that name\"\r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();
        let completion = response.into_result().unwrap_err();

        assert_eq!(completion.status, ManagesieveStatus::No);
        assert_eq!(completion.code, Some(ManagesieveResponseCode::Nonexistent));
        assert_eq!(
            completion.to_string(),
            "NO (NONEXISTENT) There is no script by that name"
        );
    }

    #[test]
    fn reads_a_quota_detail_and_falls_back_to_the_level_above() {
        let cases = [
            (
                &b"NO (QUOTA/MAXSIZE) \"too big\"\r\n"[..],
                ManagesieveResponseCode::Quota(Some(ManagesieveQuota::MaxSize)),
            ),
            (
                &b"NO (QUOTA/MAXSCRIPTS) \"too many\"\r\n"[..],
                ManagesieveResponseCode::Quota(Some(ManagesieveQuota::MaxScripts)),
            ),
            (
                &b"NO (QUOTA/SOMETHINGELSE) \"nope\"\r\n"[..],
                ManagesieveResponseCode::Quota(None),
            ),
            (
                &b"NO (LIMIT/CONNECTIONS) \"nope\"\r\n"[..],
                ManagesieveResponseCode::Other(String::from("LIMIT/CONNECTIONS")),
            ),
        ];

        for (buf, expected) in cases {
            let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();
            assert_eq!(response.completion.code, Some(expected));
        }
    }

    #[test]
    fn parses_a_response_code_carrying_a_literal_argument() {
        let buf = b"OK (TAG {16}\r\nSTARTTLS-SYNC-42) \"Done\"\r\n";
        let (response, consumed) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(consumed, buf.len());
        assert_eq!(
            response.completion.code,
            Some(ManagesieveResponseCode::Tag(String::from(
                "STARTTLS-SYNC-42"
            )))
        );
        assert_eq!(response.completion.text.unwrap(), "Done");
    }

    #[test]
    fn parses_a_multiline_rejection_text_sent_as_a_literal() {
        let buf = b"NO {30}\r\nline 2: Syntax error\r\nline 3: \r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(
            response.completion.text.unwrap(),
            "line 2: Syntax error\r\nline 3: "
        );
    }

    #[test]
    fn renders_a_response_for_a_diagnostic_command() {
        let buf = b"\"main\" ACTIVE\r\n{7}\r\nsummer\n\r\nOK (WARNINGS) \"careful\"\r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(
            response.to_string(),
            "\"main\" ACTIVE\n\"summer\\n\"\nOK (WARNINGS) careful"
        );
    }

    #[test]
    fn reports_an_incomplete_response() {
        let buf = b"\"IMPLEMENTATION\" \"Example1\"\r\n";
        assert_eq!(ManagesieveResponse::parse(buf).unwrap(), None);
    }

    #[test]
    fn refuses_an_unknown_completion_status() {
        let err = ManagesieveResponse::parse(b"MAYBE\r\n").unwrap_err();
        let ManagesieveResponseParseError::UnknownStatus(status) = err else {
            panic!("expected UnknownStatus, got {err:?}");
        };
        assert_eq!(status, "MAYBE");
    }

    #[test]
    fn refuses_an_unterminated_response_code() {
        let err = ManagesieveResponse::parse(b"NO (NONEXISTENT \"oops\"\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::UnterminatedResponseCode
        ));

        let err = ManagesieveResponse::parse(b"NO () \"oops\"\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::EmptyResponseCode
        ));
    }

    #[test]
    fn keeps_malformed_utf8_readable_rather_than_failing() {
        let buf = b"NO \"caf\xe9\"\r\n";
        let (response, _) = ManagesieveResponse::parse(buf).unwrap().unwrap();

        assert_eq!(response.completion.text.unwrap(), "caf\u{fffd}");
    }

    #[test]
    fn refuses_a_line_opening_on_a_parenthesis() {
        let err = ManagesieveResponse::parse(b"(FOO)\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::UnexpectedByte(b'(')
        ));

        let err = ManagesieveResponse::parse(b"\"name\" (FOO)\r\n").unwrap_err();
        assert!(matches!(
            err,
            ManagesieveResponseParseError::UnexpectedByte(b'(')
        ));

        let err = ManagesieveResponse::parse(b"\r\n").unwrap_err();
        assert!(matches!(err, ManagesieveResponseParseError::EmptyLine));
    }

    #[test]
    fn renders_every_response_code_it_models() {
        let codes = vec![
            (ManagesieveResponseCode::AuthTooWeak, "AUTH-TOO-WEAK"),
            (ManagesieveResponseCode::EncryptNeeded, "ENCRYPT-NEEDED"),
            (ManagesieveResponseCode::Quota(None), "QUOTA"),
            (
                ManagesieveResponseCode::Referral(String::from("sieve://a")),
                "REFERRAL sieve://a",
            ),
            (ManagesieveResponseCode::Sasl(vec![]), "SASL"),
            (
                ManagesieveResponseCode::TransitionNeeded,
                "TRANSITION-NEEDED",
            ),
            (ManagesieveResponseCode::TryLater, "TRYLATER"),
            (ManagesieveResponseCode::Active, "ACTIVE"),
            (ManagesieveResponseCode::Nonexistent, "NONEXISTENT"),
            (ManagesieveResponseCode::AlreadyExists, "ALREADYEXISTS"),
            (ManagesieveResponseCode::Warnings, "WARNINGS"),
            (
                ManagesieveResponseCode::Quota(Some(ManagesieveQuota::MaxScripts)),
                "QUOTA/MAXSCRIPTS",
            ),
            (
                ManagesieveResponseCode::Quota(Some(ManagesieveQuota::MaxSize)),
                "QUOTA/MAXSIZE",
            ),
            (
                ManagesieveResponseCode::Tag(String::from("sync-1")),
                "TAG sync-1",
            ),
            (
                ManagesieveResponseCode::Other(String::from("LIMIT/CONNECTIONS")),
                "LIMIT/CONNECTIONS",
            ),
        ];

        for (code, rendered) in codes {
            assert_eq!(code.to_string(), rendered);
        }

        assert_eq!(ManagesieveStatus::Bye.to_string(), "BYE");
    }
}
