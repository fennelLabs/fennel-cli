use jsonrpc_http_server::jsonrpc_core::IoHandler;
use jsonrpc_http_server::ServerBuilder;

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
	#[rpc(name = "add")]
	fn add(&self, a: u64, b: u64) -> Result<u64>;
}

pub struct RpcImpl;
impl Rpc for RpcImpl {
	fn add(&self, a: u64, b: u64) -> Result<u64> {
		Ok(a + b)
	}
}

pub fn start_rpc() {
	let mut io = IoHandler::new();
	
	io.extend_with(RpcImpl.to_delegate());

	let server = ServerBuilder::new(io)
		.threads(3)
		.start_http(&"127.0.0.1:9030".parse().unwrap())
		.unwrap();

	server.wait();
}