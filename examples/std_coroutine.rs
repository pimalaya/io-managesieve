//! Drives the coroutines by hand over a blocking std stream: read the
//! greeting, authenticate, list the scripts, log out.
//!
//! This is the layer a caller reaches for when it owns its transport,
//! whatever that is. Every coroutine is pumped by the same loop, which
//! is why the loop is written once here and reused.

use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
};

use io_managesieve::{
    coroutine::{ManagesieveCoroutine, ManagesieveCoroutineState, ManagesieveYield},
    rfc5804::{
        authenticate::{ManagesieveAuthenticate, ManagesieveAuthenticateOptions},
        greeting::ManagesieveGreetingGet,
        listscripts::ManagesieveScriptList,
        logout::ManagesieveLogout,
    },
};
use io_sasl::rfc4616::plain::SaslPlainCreds;

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST should be defined");
    let port: u16 = env::var("PORT")
        .expect("PORT should be defined")
        .parse()
        .expect("PORT should be a number");
    let login = env::var("LOGIN").expect("LOGIN should be defined");
    let password = env::var("PASSWORD").expect("PASSWORD should be defined");

    let mut stream = TcpStream::connect((host.as_str(), port)).expect("should connect");

    let capabilities = run(&mut stream, ManagesieveGreetingGet::new()).expect("should greet");
    println!("capabilities: {capabilities}");

    let creds = SaslPlainCreds {
        authzid: None,
        authcid: login,
        passwd: password.into(),
    };

    let opts = ManagesieveAuthenticateOptions {
        initial_response: true,
        ensure_capabilities: true,
    };

    let capabilities =
        run(&mut stream, ManagesieveAuthenticate::new(creds, opts)).expect("should authenticate");
    println!("owner: {:?}", capabilities.owner());

    let scripts = run(&mut stream, ManagesieveScriptList::new()).expect("should list scripts");

    for script in scripts {
        println!("{script}");
    }

    run(&mut stream, ManagesieveLogout::new()).expect("should log out");
}

/// Pumps one coroutine to completion against a blocking stream.
fn run<C, T, E>(stream: &mut TcpStream, mut coroutine: C) -> Result<T, E>
where
    C: ManagesieveCoroutine<Yield = ManagesieveYield, Return = Result<T, E>>,
{
    let mut buf = [0; 4096];
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("should write");
            }
            ManagesieveCoroutineState::Yielded(ManagesieveYield::WantsRead) => {
                let count = stream.read(&mut buf).expect("should read");
                arg = Some(&buf[..count]);
            }
            ManagesieveCoroutineState::Complete(result) => return result,
        }
    }
}
