//! Whole exchanges against a scripted server, over a real socket.
//!
//! The unit tests next to each coroutine feed it bytes directly, which
//! proves the state machine and nothing about the layers around it.
//! These drive the public client instead, so the framing, the command
//! serialisers, the response parser and the pump all have to agree
//! before a test passes. The server is scripted rather than
//! conditional: it asserts the exact bytes it expects, so a change to
//! what a command puts on the wire fails here rather than against
//! somebody's mail server.

#![cfg(feature = "client")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::{self, JoinHandle},
};

use io_managesieve::{
    client::{ManagesieveClient, ManagesieveClientError, ManagesieveClientStd},
    rfc5804::{
        authenticate::ManagesieveAuthenticateOptions,
        response::{ManagesieveResponseCode, ManagesieveStatus},
    },
};
use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds, rfc4752::gssapi::SaslGssapiCreds};

const GREETING: &[u8] = b"\"IMPLEMENTATION\" \"Fake ManageSieved\"\r\n\
                          \"SASL\" \"PLAIN\"\r\n\
                          \"SIEVE\" \"fileinto vacation\"\r\n\
                          \"VERSION\" \"1.0\"\r\n\
                          OK\r\n";

const SCRIPT: &[u8] = b"require [\"fileinto\"];\n";

const AUTH_PLAIN: &[u8] = b"AUTHENTICATE \"PLAIN\" \"AGFsaWNlAHNlY3JldA==\"\r\n";

#[test]
fn a_whole_script_lifecycle_runs_over_one_connection() {
    let (mut client, server) = serve(vec![
        (AUTH_PLAIN.to_vec(), b"OK \"Logged in.\"\r\n".to_vec()),
        (b"HAVESPACE \"main\" 22\r\n".to_vec(), b"OK\r\n".to_vec()),
        (
            [
                b"PUTSCRIPT \"main\" {22+}\r\n".to_vec(),
                SCRIPT.to_vec(),
                b"\r\n".to_vec(),
            ]
            .concat(),
            b"OK (WARNINGS) \"line 1: nothing is filed\"\r\n".to_vec(),
        ),
        (
            b"LISTSCRIPTS\r\n".to_vec(),
            b"\"main\"\r\n{7}\r\nsummer\n ACTIVE\r\nOK\r\n".to_vec(),
        ),
        (
            b"GETSCRIPT \"main\"\r\n".to_vec(),
            [
                b"{22}\r\n".to_vec(),
                SCRIPT.to_vec(),
                b"\r\nOK\r\n".to_vec(),
            ]
            .concat(),
        ),
        (b"SETACTIVE \"main\"\r\n".to_vec(), b"OK\r\n".to_vec()),
        (b"SETACTIVE \"\"\r\n".to_vec(), b"OK\r\n".to_vec()),
        (
            b"RENAMESCRIPT \"main\" \"backup\"\r\n".to_vec(),
            b"OK\r\n".to_vec(),
        ),
        (b"DELETESCRIPT \"backup\"\r\n".to_vec(), b"OK\r\n".to_vec()),
        (
            b"NOOP \"sync-1\"\r\n".to_vec(),
            b"OK (TAG {6}\r\nsync-1) \"Done\"\r\n".to_vec(),
        ),
        (b"LOGOUT\r\n".to_vec(), b"OK\r\n".to_vec()),
    ]);

    let capabilities = client.greeting().unwrap();
    assert_eq!(capabilities.implementation().unwrap(), "Fake ManageSieved");
    assert_eq!(capabilities.sasl(), ["PLAIN"]);
    assert_eq!(capabilities.version().unwrap(), "1.0");

    let opts = ManagesieveAuthenticateOptions {
        initial_response: true,
        ..Default::default()
    };

    client.authenticate(plain(), opts).unwrap();
    client
        .have_space("main".into(), SCRIPT.len() as u32)
        .unwrap();

    let warnings = client.put_script("main".into(), SCRIPT.to_vec()).unwrap();
    assert_eq!(warnings.unwrap(), "line 1: nothing is filed");

    let scripts = client.list_scripts().unwrap();
    assert_eq!(scripts.len(), 2);
    assert_eq!(scripts[0].name, "main");
    assert!(!scripts[0].active);
    // NOTE: a literal name keeps whatever bytes it was stored with,
    // newline included, which a quoted name could not carry.
    assert_eq!(scripts[1].name, "summer\n");
    assert!(scripts[1].active);

    assert_eq!(client.get_script("main".into()).unwrap(), SCRIPT);

    client.activate_script(Some("main".into())).unwrap();
    client.activate_script(None).unwrap();
    client
        .rename_script("main".into(), "backup".into())
        .unwrap();
    client.delete_script("backup".into()).unwrap();

    let tag = client.noop(Some("sync-1".into())).unwrap();
    assert_eq!(tag.unwrap(), "sync-1");

    client.logout().unwrap();

    server.join().unwrap();
}

#[test]
fn a_caller_upgrading_by_hand_swaps_the_stream_between_commands() {
    // NOTE: the sequence the light client documents. Nothing here
    // negotiates TLS, the point being that a caller may replace the
    // stream between two commands and carry on against the same
    // session.
    let (address, server) = spawn(vec![
        (b"STARTTLS\r\n".to_vec(), b"OK\r\n".to_vec()),
        (b"UNAUTHENTICATE\r\n".to_vec(), b"OK\r\n".to_vec()),
    ]);

    let stream = TcpStream::connect(address).unwrap();
    let upgraded = stream.try_clone().unwrap();
    let mut client = ManagesieveClientStd::new(stream);

    let capabilities = client.greeting().unwrap();
    assert!(!capabilities.starttls());
    assert!(ManagesieveClientStd::default_alpn().is_empty());
    assert_eq!(ManagesieveClientStd::default_port("sieve"), 4190);

    client.starttls().unwrap();
    client.set_stream(upgraded);
    client.unauthenticate().unwrap();

    server.join().unwrap();
}

#[test]
fn a_rejection_carries_its_response_code_all_the_way_up() {
    let (mut client, server) = serve(vec![
        (
            b"DELETESCRIPT \"main\"\r\n".to_vec(),
            b"NO (ACTIVE) \"You may not delete an active script\"\r\n".to_vec(),
        ),
        (
            b"CHECKSCRIPT {20+}\r\nInvalidSieveCommand\n\r\n".to_vec(),
            b"NO {20}\r\nline 1: Syntax error\r\n".to_vec(),
        ),
        (
            b"DELETESCRIPT \"main\"\r\n".to_vec(),
            b"NO (ACTIVE) \"nope\"\r\n".to_vec(),
        ),
    ]);

    client.greeting().unwrap();

    let err = client.delete_script("main".into()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "ManageSieve DELETESCRIPT failed: NO (ACTIVE) You may not delete an active script"
    );

    let err = client
        .check_script(b"InvalidSieveCommand\n".to_vec())
        .unwrap_err();
    assert!(err.to_string().contains("line 1: Syntax error"));

    // NOTE: the raw passthrough hands a rejection back rather than
    // raising it, since seeing the reply is what a caller asked for.
    let response = client.raw(b"DELETESCRIPT \"main\"".to_vec()).unwrap();
    assert_eq!(response.completion.status, ManagesieveStatus::No);
    assert_eq!(
        response.completion.code,
        Some(ManagesieveResponseCode::Active)
    );

    server.join().unwrap();
}

#[cfg(feature = "scram")]
#[test]
fn scram_runs_its_whole_exchange_and_verifies_the_server() {
    use io_sasl::{rfc5801::SaslGs2ChannelBinding, rfc5802::SaslScramCreds};

    // NOTE: the exchange published in RFC 7677 section 3, base64 as
    // ManageSieve carries it. Reproducing it whole is what proves the
    // framing carries SCRAM rather than merely compiling against it.
    const CLIENT_FIRST: &str = "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=";
    const SERVER_FIRST: &str = "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";
    const CLIENT_FINAL: &str = "Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTUhnc3FtbWl6N0FuZFZRPQ==";
    const SERVER_FINAL: &str = "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==";

    let (mut client, server) = serve(vec![
        (
            format!("AUTHENTICATE \"SCRAM-SHA-256\" \"{CLIENT_FIRST}\"\r\n").into_bytes(),
            format!("\"{SERVER_FIRST}\"\r\n").into_bytes(),
        ),
        (
            format!("\"{CLIENT_FINAL}\"\r\n").into_bytes(),
            // NOTE: the server-final rides in the SASL response code,
            // which is the round trip RFC 5804 section 2.1 lets a
            // server save, and which a mutual mechanism still has to be
            // given before the exchange is closed.
            format!("OK (SASL \"{SERVER_FINAL}\")\r\n").into_bytes(),
        ),
    ]);

    client.greeting().unwrap();

    let creds = SaslScramCreds {
        username: String::from("user"),
        password: String::from("pencil").into(),
        nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    };

    let opts = ManagesieveAuthenticateOptions {
        initial_response: true,
        ..Default::default()
    };

    client.authenticate(Sasl::ScramSha256(creds), opts).unwrap();

    server.join().unwrap();
}

#[cfg(feature = "scram")]
#[test]
fn scram_refuses_an_exchange_that_ended_before_it_verified_anything() {
    use io_sasl::{rfc5801::SaslGs2ChannelBinding, rfc5802::SaslScramCreds};

    const CLIENT_FIRST: &str = "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=";

    let (mut client, server) = serve(vec![(
        format!("AUTHENTICATE \"SCRAM-SHA-256\" \"{CLIENT_FIRST}\"\r\n").into_bytes(),
        b"OK \"Logged in.\"\r\n".to_vec(),
    )]);

    client.greeting().unwrap();

    let creds = SaslScramCreds {
        username: String::from("user"),
        password: String::from("pencil").into(),
        nonce: b"rOprNGfwEbeRWgbNEkqO".to_vec(),
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    };

    let opts = ManagesieveAuthenticateOptions {
        initial_response: true,
        ..Default::default()
    };

    // NOTE: a success reply cannot stand in for a proof the server
    // never gave, which is the whole point of mutual authentication.
    let err = client
        .authenticate(Sasl::ScramSha256(creds), opts)
        .unwrap_err();

    assert!(err.to_string().contains("server signature"));

    server.join().unwrap();
}

#[test]
fn an_unsupported_mechanism_is_named_rather_than_skipped() {
    let (mut client, server) = serve(Vec::new());

    client.greeting().unwrap();

    let creds = SaslGssapiCreds {
        token: b"token".to_vec(),
    };

    let err = client
        .authenticate(creds.into(), Default::default())
        .unwrap_err();

    let ManagesieveClientError::Authenticate(err) = err else {
        panic!("expected an authenticate error, got {err:?}");
    };

    assert_eq!(
        err.to_string(),
        "ManageSieve AUTHENTICATE failed: GSSAPI mechanism is not supported by this crate"
    );

    drop(client);
    server.join().unwrap();
}

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
mod connect {
    use io_managesieve::{
        client::ManagesieveClientStd,
        session::{ManagesieveSessionOpenError, ManagesieveSessionOpenOptions},
    };
    use io_sasl::mechanism::SaslMechanism;
    use pimalaya_stream::tls::Tls;
    use url::Url;

    use crate::{AUTH_PLAIN, plain, spawn};

    #[test]
    fn a_cleartext_session_opens_end_to_end_when_the_caller_allows_it() {
        let (address, server) = spawn(vec![
            (AUTH_PLAIN.to_vec(), b"OK \"Logged in.\"\r\n".to_vec()),
            (
                b"CAPABILITY\r\n".to_vec(),
                b"\"OWNER\" \"alice@example.org\"\r\n\"SIEVE\" \"fileinto\"\r\nOK\r\n".to_vec(),
            ),
        ]);

        let url = Url::parse(&format!("sieve://{address}")).unwrap();

        let opts = ManagesieveSessionOpenOptions {
            allow_cleartext_auth: true,
            ..Default::default()
        };

        let (client, capabilities) =
            ManagesieveClientStd::connect(&url, &Tls::default(), Some(plain()), opts).unwrap();

        assert_eq!(capabilities.owner().unwrap(), "alice@example.org");

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn a_cleartext_session_refuses_to_send_the_password_by_default() {
        let (address, server) = spawn(Vec::new());
        let url = Url::parse(&format!("sieve://{address}")).unwrap();
        let opts = ManagesieveSessionOpenOptions::default();

        let err =
            ManagesieveClientStd::connect(&url, &Tls::default(), Some(plain()), opts).unwrap_err();

        assert!(matches!(
            err,
            io_managesieve::client::ManagesieveClientError::SessionOpen(
                ManagesieveSessionOpenError::CleartextAuth(SaslMechanism::Plain)
            )
        ));

        server.join().unwrap();
    }
}

fn plain() -> Sasl {
    SaslPlainCreds {
        authzid: None,
        authcid: String::from("alice"),
        passwd: String::from("secret").into(),
    }
    .into()
}

/// Starts a server answering `script` in order, and a client wired to
/// it.
fn serve(script: Vec<(Vec<u8>, Vec<u8>)>) -> (ManagesieveClientStd, JoinHandle<()>) {
    let (address, server) = spawn(script);
    let stream = TcpStream::connect(address).unwrap();

    (ManagesieveClientStd::new(stream), server)
}

/// Starts a server answering `script` in order.
///
/// Each entry is the exact bytes the client is expected to send and the
/// reply to send back, so the server needs no grammar of its own: it
/// reads that many bytes and asserts they match.
fn spawn(script: Vec<(Vec<u8>, Vec<u8>)>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };

        stream.write_all(GREETING).unwrap();

        for (expected, reply) in script {
            let mut request = vec![0; expected.len()];

            if stream.read_exact(&mut request).is_err() {
                panic!(
                    "client closed before sending {}",
                    String::from_utf8_lossy(&expected)
                );
            }

            assert_eq!(
                String::from_utf8_lossy(&request),
                String::from_utf8_lossy(&expected)
            );

            stream.write_all(&reply).unwrap();
        }
    });

    (address, server)
}
