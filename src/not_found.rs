use super::constant::STATUS404;
use hyper::{Body, Response, StatusCode};

pub async fn not_found() -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::from(STATUS404));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}
