
use vercre_wallet::http::protocol::{HttpRequest, HttpResponse};

use crate::error;

pub async fn request(http_req: &HttpRequest) -> Result<HttpResponse, error::Error> {
    let client = reqwest::Client::new();

    let Ok(method) = reqwest::Method::try_from(http_req.method.as_str()) else {
        return Err(error::Error::HttpConfig(format!("invalid method {}", http_req.method)));
    };

    let mut request = client.request(method, &http_req.url);

    for header in &http_req.headers {
        request = request.header(header.name.as_str(), &header.value);
    }

    if !http_req.body.is_empty() {
        request = request.body(http_req.body.clone());
    }

    let response = request.send().await?;
    let status = response.status().into();
    let body = response.bytes().await?;

    Ok(HttpResponse::status(status).body(body).build())
}
