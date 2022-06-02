mod service;
mod traits;
mod types;

use jsonrpsee::ws_server::WsServerBuilder;
use std::net::SocketAddr;

use service::FennelRPCService;

use self::traits::FennelRPCServer;

#[allow(unreachable_code)]
pub async fn start_rpc() -> anyhow::Result<()> {
    let server = WsServerBuilder::default()
        .build("127.0.0.1:9030".parse::<SocketAddr>()?)
        .await?;

    server.local_addr()?;
    server.start(FennelRPCService.into_rpc())?;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    Ok(())
}
