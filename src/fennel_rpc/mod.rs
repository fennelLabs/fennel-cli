mod service;
mod traits;
mod types;

use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};
use std::net::SocketAddr;

use service::FennelRPCService;

use self::traits::FennelRPCServer;

pub async fn start_rpc() -> anyhow::Result<(SocketAddr, HttpServerHandle)> {
    let server = HttpServerBuilder::default()
        .build("127.0.0.1:9030".parse::<SocketAddr>()?)
        .await?;

    let addr = server.local_addr()?;
    let server_handle = server.start(FennelRPCService.into_rpc())?;
    Ok((addr, server_handle))
}
