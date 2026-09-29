//! Full std client: pass a URL and credentials, and let
//! [`ManagesieveClientStd::connect`] open TCP, negotiate TLS, read the
//! greeting, optionally upgrade via STARTTLS, then run the SASL
//! exchange. It returns the client together with the capabilities the
//! server last reported, so no extra round trip is needed to read them.
//! Requires the `rustls-ring` (or `rustls-aws` / `native-tls`) feature.
//!
//! Run with:
//! `URL=sieves://mail.example.org LOGIN=alice PASSWORD=secret cargo run --example std_client_full`

use std::{env, error::Error};

use io_managesieve::{
    client::{ManagesieveClient, ManagesieveClientStd, ManagesieveClientStdConnectOptions},
    session::ManagesieveSessionOpenOptions,
};
use io_sasl::rfc4616::plain::SaslPlainCreds;
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;

    let creds = SaslPlainCreds {
        authzid: None,
        authcid: env::var("LOGIN")?,
        passwd: env::var("PASSWORD")?.into(),
    };

    let opts = ManagesieveClientStdConnectOptions {
        sasl: Some(creds.into()),
        session: ManagesieveSessionOpenOptions {
            starttls: url.scheme() == "sieve",
            ..Default::default()
        },
        ..Default::default()
    };

    let (mut client, capabilities) = ManagesieveClientStd::connect(&url, opts)?;

    println!("{capabilities}");

    for script in client.list_scripts()? {
        println!("{script}");
    }

    client.logout()?;

    Ok(())
}
