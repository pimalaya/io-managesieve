//! The light client: one method per coroutine over a stream the caller
//! opened itself.
//!
//! Nothing here negotiates TLS, so the connection is cleartext and the
//! session is told so: PLAIN would be refused, which is the point of
//! [`std_client_full`](std_client_full), the example that connects.

use std::{env, net::TcpStream};

use io_managesieve::client::{ManagesieveClient, ManagesieveClientStd};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST should be defined");
    let port: u16 = env::var("PORT")
        .expect("PORT should be defined")
        .parse()
        .expect("PORT should be a number");

    let stream = TcpStream::connect((host.as_str(), port)).expect("should connect");
    let mut client = ManagesieveClientStd::new(stream);

    let capabilities = client.greeting().expect("should greet");
    println!("implementation: {:?}", capabilities.implementation());
    println!("sieve extensions: {:?}", capabilities.sieve());
    println!("sasl mechanisms: {:?}", capabilities.sasl());

    client.logout().expect("should log out");
}
