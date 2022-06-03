use super::constant::{STATUS401, STATUS403};
use super::jwks::get_jwk;
use crate::conf::Config;
use hyper::{header, Body, Request, Response, StatusCode};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

static INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error";

fn get_algorithm(alg: String) -> Algorithm {
    if alg == "RS256" {
        Algorithm::RS256
    } else if alg == "RS384" {
        Algorithm::RS384
    } else if alg == "RS512" {
        Algorithm::RS512
    // } else if alg == "EdDSA" {
    //     Algorithm::EdDSA
    } else {
        panic!("unsupported algorithm: {}", alg);
    }
}

struct TokenData {
    algorithm: String,
    client_id: String,
    aud: Vec<String>,
    sub: String,
    iss: String,
    scp: Vec<String>,
    signing_key: String,
    expiration: u64,
    not_before: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    client_id: String,
    aud: Vec<String>,
    sub: String,
    iss: String,
    scp: Vec<String>,
    jti: String,
    exp: u64,
    nbf: u64,
}

fn access_token(token_data: TokenData) -> String {
    // Generate a ulid
    let ulid = Ulid::new();

    // form the claims for the token
    let claims = Claims {
        client_id: token_data.client_id,
        aud: token_data.aud,
        sub: token_data.sub,
        iss: token_data.iss,
        scp: token_data.scp,
        jti: ulid.to_string(),
        exp: token_data.expiration,
        nbf: token_data.not_before,
    };

    // clone the signing key
    let sk = token_data.signing_key.clone();

    // decode the signing key
    let key_decoded = match base64::decode(token_data.signing_key) {
        Ok(kd) => kd,
        Err(err) => panic!("{:?}", err), // in practice you would return the error
    };

    // create the private key
    let private_key = match EncodingKey::from_rsa_pem(key_decoded.as_slice()) {
        Ok(pk) => pk,
        Err(err) => panic!("{:?}", err), // in practice you would return the error
    };

    // get jwk key for kid
    let key = get_jwk(token_data.algorithm.clone(), sk);

    // form the header for the token
    let header = Header {
        kid: Some(key.kid),
        alg: get_algorithm(token_data.algorithm),
        ..Default::default()
    };

    // encode the token
    let token = match encode(&header, &claims, &private_key) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    // log the token
    debug!("access token: {:?}", token);

    // return the token
    token
}

fn response_403() -> Result<Response<Body>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Body::from(STATUS403))
        .unwrap())
}

fn response_401() -> Result<Response<Body>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(STATUS401))
        .unwrap())
}

pub async fn token(req: Request<Body>, conf: &Config) -> Result<Response<Body>, hyper::Error> {
    // get authorization header
    let auth_header = match req.headers().get("authorization") {
        Some(header) => header,
        None => return response_403(),
    };

    // Check if the authorization header is valid
    let auth_header_str = match auth_header.to_str() {
        Ok(header) => header,
        Err(err) => {
            error!("{}", err);
            return response_403();
        }
    };

    // trim the prefix
    let auth_header_str = auth_header_str.trim();

    // collect the header parts
    let auth_header_parts: Vec<&str> = auth_header_str.split(' ').collect();

    // Check if the authorization header is valid
    if auth_header_parts.len() != 2 {
        error!("{}", "client credentials are not correct1");
        return response_403();
    }

    // Check if the authorization header is Basic
    let auth_header_parts = auth_header_parts[1];

    // Decode the base64 encoded string
    let auth_header_decoded = match base64::decode(auth_header_parts) {
        Ok(header) => header,
        Err(err) => {
            error!("{}", err);
            return response_403();
        }
    };

    // auth header is in the form of "Basic base64(client_id:client_secret)"
    let auth_header_decode_str = match String::from_utf8(auth_header_decoded) {
        Ok(header) => header,
        Err(err) => {
            error!("{}", err);
            return response_403();
        }
    };

    // Split the string into client_id and client_secret
    let auth_header_decode_parts: Vec<&str> = auth_header_decode_str.split(':').collect();

    // get client_id and client_secret
    let client = auth_header_decode_parts[0];
    let secret = auth_header_decode_parts[1];

    // Check if client exists
    if !conf.authorization.contains_key(client) {
        error!("{}", "client credentials are not correct");
        return response_403();
    }

    // Check if secret is correct
    if conf.authorization[client].secret != secret {
        error!("{}", "client credentials are not correct");
        return response_403();
    }

    let whole_body = hyper::body::to_bytes(req.into_body()).await?;

    let body = match String::from_utf8(whole_body.to_vec()) {
        Ok(body) => body,
        Err(err) => {
            error!("{}", err);
            return response_403();
        }
    };

    debug!("Body: {}", body);

    let body_parts: Vec<&str> = body.split('&').collect();

    if body_parts.is_empty() {
        error!("{}", "client credentials are not correct");
        return response_401();
    }

    let mut hm: HashMap<String, String> = HashMap::new();
    for body_part in body_parts {
        let body_part_split: Vec<&str> = body_part.split('=').collect();
        if body_part_split.len() < 2 {
            error!("{}", "client credentials are not correct");
            return response_401();
        }
        hm.insert(
            body_part_split[0].to_string(),
            body_part_split[1].to_string(),
        );
    }

    let grant_type = match hm.get("grant_type") {
        Some(grant_type) => grant_type,
        None => {
            error!("{}", "grant_type is not found");
            return response_401();
        }
    };

    let mut audience = "".to_string();
    if hm.contains_key(&"audience".to_string()) {
        audience = match hm.get("audience") {
            Some(audience) => audience.to_string(),
            _ => {
                error!("{}", "audience is not found");
                return response_401();
            }
        };
    }

    audience = urlencoding::decode(audience.as_str()).unwrap().to_string();
    let mut audience_list: Vec<String> = vec![];
    if !audience.is_empty() {
        audience_list = audience.split(' ').map(|s| s.to_string()).collect();
    }

    if !conf.authorization[client]
        .audience
        .contains(&"*".to_string())
    {
        for v in &audience_list {
            if !conf.authorization[client].audience.contains(v) {
                error!("{}", "audience is not found");
                return response_401();
            }
        }
    }

    let mut scope = "".to_string();
    if hm.contains_key(&"scope".to_string()) {
        scope = match hm.get("scope") {
            Some(scope) => scope.to_string(),
            _ => {
                error!("{}", "scope is not found");
                return response_401();
            }
        };
    }

    scope = urlencoding::decode(scope.as_str()).unwrap().to_string();
    let mut scope_list: Vec<String> = vec![];
    if !scope.is_empty() {
        scope_list = scope.split(' ').map(|s| s.to_string()).collect();
    }

    if !conf.authorization[client].scope.contains(&"*".to_string()) {
        for v in &scope_list {
            if !conf.authorization[client].scope.contains(v) {
                error!("{}", "scope is not found");
                return response_401();
            }
        }
    }

    if grant_type != &conf.grant_type {
        error!("{}", "grant_type is not correct");
        return response_401();
    }

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");

    let exp = since_the_epoch.as_secs() + conf.expiration;
    let nbf = since_the_epoch.as_secs();

    let token_data = TokenData {
        algorithm: conf.algorithm.clone(),
        client_id: client.to_string(),
        aud: audience_list,
        sub: conf.subject.clone(),
        iss: conf.issuer.clone(),
        scp: scope_list,
        signing_key: conf.signing_key.clone(),
        expiration: exp,
        not_before: nbf,
    };

    #[derive(Serialize, Deserialize)]
    struct Res {
        access_token: String,
        expires_in: u64,
        scope: String,
        token_type: String,
    }

    let data = Res {
        access_token: access_token(token_data),
        expires_in: conf.expiration,
        scope,
        token_type: conf.token_type.clone(),
    };

    let response = match serde_json::to_string(&data) {
        Ok(json) => Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(INTERNAL_SERVER_ERROR.into())
            .unwrap(),
    };

    Ok(response)
}
