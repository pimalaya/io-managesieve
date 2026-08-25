//! Opens a session on an async runtime, to show that the protocol
//! knowledge lives in the coroutine rather than in the std client.
//!
//! [`ManagesieveSessionOpen`] yields transport requests alongside reads
//! and writes, so a caller answers them with whatever sockets it has.
//! This one answers with tokio's, and refuses the TLS variants: adding
//! them is a tokio-rustls connector and nothing else about the exchange
//! changes.
//!
//! Run with:
//! `URL=sieve://localhost:4190 cargo run --example tokio_session --features url`

use std::{env, error::Error};

use io_managesieve::{
    coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState},
    session::{
        ManagesieveSessionOpen, ManagesieveSessionOpenOptions, ManagesieveSessionOpenYield,
        ManagesieveSessionTransport,
    },
};
use io_sasl::mechanism::Sasl;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let transport = ManagesieveSessionTransport::from_url(&url)?;
    let opts = ManagesieveSessionOpenOptions::default();

    let mut session = ManagesieveSessionOpen::new(transport, None::<Sasl>, opts);
    let mut stream: Option<TcpStream> = None;
    let mut buf = [0; 4096];
    let mut arg = None;

    let data = loop {
        match session.resume(arg.take()) {
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsTcpConnect {
                host,
                port,
            }) => {
                stream = Some(TcpStream::connect((host.as_str(), port)).await?);
            }
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsWrite(bytes)) => {
                stream
                    .as_mut()
                    .expect("stream should be open")
                    .write_all(&bytes)
                    .await?;
            }
            ManagesieveCoroutineState::Yielded(ManagesieveSessionOpenYield::WantsRead) => {
                let stream = stream.as_mut().expect("stream should be open");
                let count = stream.read(&mut buf).await?;
                arg = Some(&buf[..count]);
            }
            ManagesieveCoroutineState::Yielded(yielded) => {
                panic!("unexpected {yielded:?} over plain TCP")
            }
            ManagesieveCoroutineState::Complete(result) => break result?,
        }
    };

    println!("{}", data.capabilities);

    Ok(())
}
