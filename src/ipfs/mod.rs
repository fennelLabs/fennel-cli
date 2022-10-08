#[cfg(test)]
mod tests;
use reqwest::{Body, multipart};
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

pub async fn add_file(filename: &str) -> String {
    // https://docs.ipfs.io/reference/http/api/#api-v0-block-put
    let client = reqwest::Client::new();
    let file = File::open(filename).await?;

    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);
    let upload = multipart::Part::stream(file_body).file_name(filename).mime_str("text/plain");
    let form = multipart::Form::new().part("data", upload);

    let res = client.post("http://127.0.0.1:5001/api/v0/block/put?cid-codec=raw&mhtype=sha2-256&mhlen=-1&pin=false&allow-big-block=false")
        .body(body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    res
}

pub async fn get_file(cid: &str) -> String {
    // https://docs.ipfs.io/reference/http/api/#api-v0-block-get
    let client = reqwest::Client::new();

    let res = client
        .post(format!("http://127.0.0.1:5001/api/v0/block/get?arg={}", cid).as_str())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    res
}

pub async fn del_file(cid: &str) -> bool {
    // https://docs.ipfs.io/reference/http/api/#api-v0-block-rm
    let client = reqwest::Client::new();

    let res = client
        .post(format!("http://127.0.0.1:5001/api/v0/block/rm?arg={}", cid).as_str())
        .send()
        .await
        .unwrap()
        .status();
    res.is_success()
}
