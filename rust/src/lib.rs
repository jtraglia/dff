pub mod client;
pub mod server;

pub use client::Client;
pub use server::Server;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Client error: {0}")]
    Client(String),
}

pub type Result<T> = std::result::Result<T, Error>;