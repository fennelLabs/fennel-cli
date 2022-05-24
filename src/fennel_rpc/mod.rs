use std::net::SocketAddr;

use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle, RpcModule};

pub async fn start_rpc() -> anyhow::Result<(SocketAddr, HttpServerHandle)> {
	let server = HttpServerBuilder::default().build("127.0.0.1:9030".parse::<SocketAddr>()?).await?;
	let mut module = RpcModule::new(());
	module.register_method("say_hello", |_, _| Ok("lo"))?;

	let addr = server.local_addr()?;
	let server_handle = server.start(module)?;
	Ok((addr, server_handle))
}
