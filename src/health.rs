use hyper::{Body, Response};

pub async fn health() -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::from("{}"));
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );

    Ok(response)
}
