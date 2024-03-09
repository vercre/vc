use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use surf::http::Method;
use surf::{Client, Config, Url};
use vercre_wallet::http::protocol::{HttpRequest, HttpResponse, HttpResult};

pub(crate) async fn request(
    HttpRequest {
        url, method, headers, ..
    }: &HttpRequest,
) -> Result<HttpResult> {
    let method = Method::from_str(method).expect("unknown http method");
    let url = Url::parse(url)?;
    let headers = headers.clone();

    let client: Client = Config::new().set_timeout(Some(Duration::from_secs(5))).try_into()?;

    let mut request = client.request(method, &url);

    for header in headers {
        request = request.header(header.name.as_str(), &header.value);
    }

    let mut response = request.await.map_err(|e| anyhow!("{method} {url}: error {e}"))?;

    let status = response.status().into();

    match response.body_bytes().await {
        Ok(body) => Ok(HttpResult::Ok(HttpResponse::status(status).body(body).build())),
        Err(e) => bail!("{method} {url}: error {e}"),
    }
}
