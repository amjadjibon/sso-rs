use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use log::{debug, error};
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;

mod conf;
mod constant;
mod health;
mod jwks;
mod not_found;
mod token;

use conf::get_config_lazy;
use conf::Config;
use health::health;
use jwks::jwks;
use not_found::not_found;
use token::token;

async fn sso(req: Request<Body>, conf: &Config) -> Result<Response<Body>, hyper::Error> {
    // debug logs the request
    debug!("Path: {}", req.uri());
    debug!("Method: {}", req.method());
    debug!("Headers: {:?}", req.headers());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/_sso/health") => health().await,
        (&Method::POST, "/oauth2/token") => token(req, conf).await,
        (&Method::GET, "/.well-known/jwks.json") => jwks(conf).await,
        _ => not_found().await,
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

async fn run_server(file_name: String) {
    // get config from file
    let conf = get_config_lazy(file_name);

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([0, 0, 0, 0], conf.port));

    // A `Service` is needed for every connection, so this
    let server = Server::bind(&addr).serve(make_service_fn(move |_conn| {
        // let conf = conf.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| sso(req, conf))) }
    }));

    // And now add a graceful shutdown signal...
    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // Run this server for... forever!
    debug!("server running on http://{}", addr);
    if let Err(e) = graceful.await {
        error!("server error: {}", e);
    }
    debug!(" gracefully shutdown complete")
}

#[tokio::main]
async fn main() {
    // init logger
    env_logger::init();

    // get args from command line
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let file_name = match args.pop() {
        Some(val) => val,
        None => panic!("file not specified"),
    };

    run_server(file_name).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{body::to_bytes, Client, Method};
    use tokio::runtime::Runtime;

    #[test]
    fn test() {
        // create a runtime
        let rt = Runtime::new().unwrap();

        // start server
        rt.spawn(run_server(String::from("manifest.yaml")));

        // wait for server to come up
        std::thread::sleep(std::time::Duration::from_millis(50));

        // create a client
        let client = Client::new();

        // make requests
        let req_health = client.request(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:8080/_sso/health")
                .body(Body::empty())
                .unwrap(),
        );

        // get response
        let res_health = rt.block_on(req_health).unwrap();

        // check response
        assert_eq!(res_health.status().clone(), 200);

        // get body
        let body = rt.block_on(to_bytes(res_health.into_body())).unwrap();
        // check response
        assert_eq!(std::str::from_utf8(&body).unwrap(), "{}");

        // make requests
        let req_jwks = client.request(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:8080/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        );

        // get response
        let res_jwks = rt.block_on(req_jwks).unwrap();

        // get body
        // let body = rt.block_on(to_bytes(res.into_body())).unwrap();

        // check response
        assert_eq!(res_jwks.status().clone(), 200);

        // let body = "grant_type=client_credentials";
        // // make requests
        // let req_token = client.request(
        //     Request::builder()
        //         .method(Method::POST)
        //         .uri("http://client:secret@localhost:8080/oauth2/token")
        //         .header("Content-Type", "application/x-www-form-urlencoded")
        //         .body(Body::from(body))
        //         .unwrap(),
        // );
        //
        // // get response
        // let res_token = rt.block_on(req_token).unwrap();
        // // check response
        // assert_eq!(res_token.status().clone(), 200);
    }
}
