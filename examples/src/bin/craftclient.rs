//! This example demonstrates how to use the craft module to customize
//! the TLS ClientHello fingerprint to match a specific browser.
//!
//! It connects to a server using Chrome 108's TLS fingerprint.
//!
//! Usage:
//!   cargo run --bin craftclient --features craft

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::RootCertStore;

fn main() {
    #[cfg(feature = "craft")]
    {
        use rustls::craft::CHROME_108;

        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let config =
            rustls::ClientConfig::builder(rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER.into())
                .with_root_certificates(root_store)
                .with_no_client_auth()
                .unwrap()
                .with_fingerprint(CHROME_108.builder());

        let server_name = "www.google.com".try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect("www.google.com:443").unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        tls.write_all(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: www.google.com\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

        let ciphersuite = tls
            .conn
            .negotiated_cipher_suite()
            .unwrap();
        writeln!(
            &mut std::io::stderr(),
            "Connected with Chrome 108 fingerprint! Ciphersuite: {:?}",
            ciphersuite.suite()
        )
        .unwrap();

        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();

        // Just print first 500 chars to avoid flooding output
        let response = String::from_utf8_lossy(&plaintext);
        let preview: String = response.chars().take(500).collect();
        stdout().write_all(preview.as_bytes()).unwrap();
        println!("\n\n... (response truncated)");
    }

    #[cfg(not(feature = "craft"))]
    {
        eprintln!("This example requires the 'craft' feature.");
        eprintln!("Run with: cargo run --bin craftclient --features craft");
    }
}
