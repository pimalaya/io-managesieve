//! Every mechanism the build carries, against the name it goes out
//! under.
//!
//! `rfc5804::authenticate` dispatches on a dozen near-identical arms,
//! each of which typechecks against its own credentials, so no compiler
//! catches two of them landing on the same mechanism. What a walk over
//! all of them catches is exactly that, which is why this is one table
//! rather than a test per mechanism.

use io_managesieve::{
    coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState, ManagesieveYield},
    rfc5804::authenticate::{ManagesieveAuthenticate, ManagesieveAuthenticateOptions},
};
use io_sasl::{
    login::SaslLoginCreds, mechanism::Sasl, rfc4422::external::SaslExternalCreds,
    rfc4505::anonymous::SaslAnonymousCreds, rfc4616::plain::SaslPlainCreds,
    rfc5801::SaslGs2ChannelBinding, rfc7628::oauthbearer::SaslOauthbearerCreds,
    xoauth2::SaslXoauth2Creds,
};
use secrecy::SecretString;

#[cfg(feature = "cram-md5")]
use io_sasl::rfc2195::cram_md5::SaslCramMd5Creds;
#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;

#[test]
fn every_mechanism_goes_out_under_the_name_it_is_registered_with() {
    let mut named: Vec<&str> = Vec::new();

    for sasl in vocabulary() {
        let expected = sasl.mechanism().as_str();

        assert!(
            !named.contains(&expected),
            "{expected} is claimed by two credential types"
        );

        named.push(expected);

        let opts = ManagesieveAuthenticateOptions {
            initial_response: true,
            ..Default::default()
        };

        let mut auth = ManagesieveAuthenticate::new(sasl, opts);

        let bytes = match auth.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite for {expected}, got {state:?}"),
        };

        let line = String::from_utf8(bytes).expect("utf8 command");

        assert!(
            line.starts_with(&format!("AUTHENTICATE \"{expected}\"")),
            "{expected} went out as {line:?}"
        );
    }
}

#[test]
fn a_server_first_mechanism_sends_no_initial_response() {
    // NOTE: LOGIN prompts for the username, so RFC 5804 section 2.1
    // forbids an initial response even though io-sasl computes that
    // username without a challenge. CRAM-MD5 is server-first outright.
    let opts = ManagesieveAuthenticateOptions {
        initial_response: true,
        ..Default::default()
    };

    for (sasl, expected) in server_first() {
        let mut auth = ManagesieveAuthenticate::new(sasl, opts.clone());

        let bytes = match auth.resume(None) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }
}

/// Every mechanism this build carries credentials for.
fn vocabulary() -> Vec<Sasl> {
    let mut vocabulary: Vec<Sasl> = vec![
        SaslAnonymousCreds { message: None }.into(),
        SaslExternalCreds { authzid: None }.into(),
        SaslLoginCreds {
            username: "alice".into(),
            password: SecretString::from("pencil"),
        }
        .into(),
        SaslPlainCreds {
            authzid: None,
            authcid: "alice".into(),
            passwd: SecretString::from("pencil"),
        }
        .into(),
        SaslOauthbearerCreds {
            username: "alice@localhost".into(),
            host: "localhost".into(),
            port: 4190,
            token: SecretString::from("vF9dft4qmT"),
        }
        .into(),
        SaslXoauth2Creds {
            username: "alice@localhost".into(),
            token: SecretString::from("vF9dft4qmT"),
        }
        .into(),
    ];

    vocabulary.extend(cram_md5());
    vocabulary.extend(scram());
    vocabulary
}

/// The mechanisms that speak second, with the bare command they send.
fn server_first() -> Vec<(Sasl, &'static str)> {
    let mut mechanisms: Vec<(Sasl, &'static str)> = vec![(
        SaslLoginCreds {
            username: "alice".into(),
            password: SecretString::from("pencil"),
        }
        .into(),
        "AUTHENTICATE \"LOGIN\"\r\n",
    )];

    mechanisms.extend(
        cram_md5()
            .into_iter()
            .map(|sasl| (sasl, "AUTHENTICATE \"CRAM-MD5\"\r\n")),
    );

    mechanisms
}

#[cfg(feature = "cram-md5")]
fn cram_md5() -> Vec<Sasl> {
    vec![
        SaslCramMd5Creds {
            username: "alice".into(),
            secret: SecretString::from("pencil"),
        }
        .into(),
    ]
}

#[cfg(not(feature = "cram-md5"))]
fn cram_md5() -> Vec<Sasl> {
    Vec::new()
}

#[cfg(feature = "scram")]
fn scram() -> Vec<Sasl> {
    let creds = || SaslScramCreds {
        username: "alice".into(),
        password: SecretString::from("pencil"),
        nonce: b"fyko+d2lbbFgONRv9qkxdawL".to_vec(),
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    };

    vec![
        Sasl::ScramSha1(creds()),
        Sasl::ScramSha256(creds()),
        Sasl::ScramSha512(creds()),
    ]
}

#[cfg(not(feature = "scram"))]
fn scram() -> Vec<Sasl> {
    let _ = SaslGs2ChannelBinding::Unsupported;
    Vec::new()
}
