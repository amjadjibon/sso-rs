use crate::conf::Config;
use base64::encode;
use data_encoding::BASE32HEX;
use hyper::{header, Body, Response, StatusCode};
use log::debug;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

static INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error";

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub n: String,
    pub e: String,
}

pub fn get_jwk(algorithm: String, signing_key: String) -> Key {
    let signing_key_decoded = base64::decode(signing_key).unwrap();
    let signing_key_decoded_str = String::from_utf8(signing_key_decoded).unwrap();

    let rsa = Rsa::private_key_from_pem(signing_key_decoded_str.as_bytes()).unwrap();

    let n = encode(&rsa.n().to_vec()).trim_end_matches('=').to_string();
    let e = encode(&rsa.e().to_vec()).trim_end_matches('=').to_string();

    // create a Sha1 object
    let mut hasher = Sha1::new();
    // process input message
    hasher.update(rsa.n().to_vec());
    hasher.update(rsa.e().to_vec());

    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    let result = hasher.finalize();

    let kid = BASE32HEX.encode(result.as_slice());

    Key {
        kid,
        kty: "RSA".to_string(),
        alg: algorithm,
        use_: "sig".to_string(),
        n,
        e,
    }
}

pub async fn jwks(conf: &Config) -> Result<Response<Body>, hyper::Error> {
    #[derive(Serialize, Deserialize)]
    struct Keys {
        keys: Vec<Key>,
    }

    let key = get_jwk(conf.algorithm.clone(), conf.signing_key.clone());

    let k = Key {
        kid: key.kid.to_string(),
        kty: key.kty.to_string(),
        alg: key.alg.to_string(),
        use_: key.use_.to_string(),
        n: key.n,
        e: key.e,
    };

    debug!("JWK: {:?}", k);

    let data = Keys { keys: vec![k] };

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
