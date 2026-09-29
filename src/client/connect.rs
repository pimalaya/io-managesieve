//! End-to-end connect for the std client, the half that needs a TLS
//! provider.
//!
//! The module is gated once where it is declared, so nothing inside
//! repeats the feature list. It holds [`ManagesieveClientStd::connect`]
//! and the one decision the coroutines cannot make for themselves:
//! drawing a SCRAM client nonce when the caller supplied none.

#[cfg(feature = "scram")]
use alloc::vec::Vec;

use std::io::{self, Read, Write};

use io_sasl::mechanism::Sasl;
#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;
use pimalaya_stream::{
    proxy::Proxy,
    stream::{Stream, TcpConnectOptions, TlsConnectOptions, UnixConnectOptions},
    tls::Tls,
};
#[cfg(feature = "scram")]
use rand::{RngExt, distr::Alphanumeric, rng};
use url::Url;

use crate::{
    client::{ManagesieveClientError, ManagesieveClientStd, READ_BUFFER_SIZE},
    coroutine::*,
    rfc5804::capability::ManagesieveCapabilities,
    session::*,
};

/// Optional settings for [`ManagesieveClientStd::connect`].
///
/// The default uses the TLS backend default, resolves the proxy from
/// the environment, skips authentication and follows the session
/// defaults.
#[derive(Clone, Debug, Default)]
pub struct ManagesieveClientStdConnectOptions {
    /// How the TLS transports are secured, implicit or via STARTTLS
    /// (see [`ManagesieveSessionOpenOptions::starttls`]).
    ///
    /// It carries the rustls/native-tls options and the ALPN list,
    /// which is empty by default because ManageSieve has no registered
    /// identifier (see [`ManagesieveClientStd::default_alpn`]).
    pub tls: Tls,
    /// How the TCP and TLS transports reach the server.
    ///
    /// [`Proxy::System`] resolves it from the environment,
    /// [`Proxy::None`] connects directly. A local socket ignores it.
    pub proxy: Proxy,
    /// The SASL mechanism to authenticate with, `None` skipping
    /// authentication, since ManageSieve has no pre-authenticated
    /// greeting to skip it for you.
    ///
    /// SCRAM credentials carrying an empty nonce are given one drawn at
    /// connect time, an empty nonce being no nonce at all as far as RFC
    /// 5802 is concerned; a caller wanting its own passes it in the
    /// credentials.
    pub sasl: Option<Sasl>,
    /// The protocol options handed to [`ManagesieveSessionOpen`].
    pub session: ManagesieveSessionOpenOptions,
}

impl ManagesieveClientStd {
    /// End-to-end connect: TCP/TLS, greeting, optional STARTTLS with a
    /// second capability read, optional SASL.
    ///
    /// `sieve://` is plain TCP, `sieves://` is implicit TLS and
    /// `unix://` is a local socket reaching a proxy; both network
    /// schemes default to port 4190, which is the only one ManageSieve
    /// registers. `opts.session.starttls = true` is only valid on a
    /// cleartext transport.
    ///
    /// Every protocol decision belongs to [`ManagesieveSessionOpen`],
    /// including the refusal to send a password over a cleartext
    /// connection; this method only answers its transport requests with
    /// [`Stream`]. A caller on another runtime pumps the same coroutine
    /// with its own sockets.
    ///
    /// Returns the authenticated client and the capabilities the server
    /// last reported.
    pub fn connect(
        url: &Url,
        opts: ManagesieveClientStdConnectOptions,
    ) -> Result<(Self, ManagesieveCapabilities), ManagesieveClientError> {
        let ManagesieveClientStdConnectOptions {
            tls,
            proxy,
            sasl,
            session,
        } = opts;

        let transport = ManagesieveSessionTransport::from_url(url)?;
        let sasl = sasl.map(with_client_nonce);
        let mut session = ManagesieveSessionOpen::new(transport, sasl, session);
        let mut stream: Option<Stream> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: the state machine always asks for a connect before any
        // read, write or upgrade, so the stream is open by the time
        // those arrive.
        let missing = || io::Error::other("ManageSieve session yielded I/O before connecting");

        loop {
            match session.resume(arg.take()) {
                ManagesieveCoroutineState::Complete(Err(err)) => return Err(err.into()),
                ManagesieveCoroutineState::Complete(Ok(data)) => {
                    let stream = stream.ok_or_else(missing)?;
                    return Ok((Self::new(stream), data.capabilities));
                }
                ManagesieveCoroutineState::Yielded(
                    ManagesieveSessionOpenYield::WantsTcpConnect { host, port },
                ) => {
                    let opts = TcpConnectOptions {
                        proxy: proxy.clone(),
                        ..Default::default()
                    };

                    stream = Some(Stream::connect_tcp(host, port, opts)?);
                }
                ManagesieveCoroutineState::Yielded(
                    ManagesieveSessionOpenYield::WantsTlsConnect { host, port },
                ) => {
                    let opts = TlsConnectOptions {
                        tls: tls.clone(),
                        proxy: proxy.clone(),
                        ..Default::default()
                    };

                    stream = Some(Stream::connect_tls(host, port, opts)?);
                }
                ManagesieveCoroutineState::Yielded(
                    ManagesieveSessionOpenYield::WantsUnixConnect(path),
                ) => {
                    let opts = UnixConnectOptions::default();
                    stream = Some(Stream::connect_unix(path, opts)?);
                }
                ManagesieveCoroutineState::Yielded(
                    ManagesieveSessionOpenYield::WantsTlsUpgrade,
                ) => {
                    let plain = stream.take().ok_or_else(missing)?;
                    stream = Some(plain.upgrade_tls(&tls)?);
                }
                ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsRead) => {
                    let count = stream.as_mut().ok_or_else(missing)?.read(&mut buf)?;
                    arg = Some(&buf[..count]);
                }
                ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(
                    bytes,
                )) => {
                    stream.as_mut().ok_or_else(missing)?.write_all(&bytes)?;
                }
            }
        }
    }
}

/// Draws the SCRAM client nonce a caller left empty.
///
/// RFC 5802 asks for printable ASCII without commas, hence the
/// alphanumeric sample, and at least 18 bytes of randomness. The
/// coroutines take the nonce as an input so they stay free of
/// randomness; this is where the std client makes that decision.
#[cfg(feature = "scram")]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    let nonce = || -> Vec<u8> { rng().sample_iter(Alphanumeric).take(24).collect() };

    match sasl {
        Sasl::ScramSha1(creds) if creds.nonce.is_empty() => Sasl::ScramSha1(SaslScramCreds {
            nonce: nonce(),
            ..creds
        }),
        Sasl::ScramSha256(creds) if creds.nonce.is_empty() => Sasl::ScramSha256(SaslScramCreds {
            nonce: nonce(),
            ..creds
        }),
        Sasl::ScramSha512(creds) if creds.nonce.is_empty() => Sasl::ScramSha512(SaslScramCreds {
            nonce: nonce(),
            ..creds
        }),
        sasl => sasl,
    }
}

/// Stands in when the scram feature is off: no mechanism reads a nonce.
#[cfg(not(feature = "scram"))]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    sasl
}
