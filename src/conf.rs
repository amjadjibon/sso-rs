use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use std::{collections::HashMap, fs::File};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub expiration: u64,
    pub algorithm: String,
    pub subject: String,
    pub signing_key: String,
    pub issuer: String,
    pub token_type: String,
    pub grant_type: String,
    pub authorization: HashMap<String, Authorization>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Authorization {
    pub secret: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub audience: Vec<String>,
}

pub fn get_config(path: String) -> Config {
    let f = File::open(path);
    let mut f = match f {
        Ok(file) => file,
        Err(e) => panic!("Could not open config file: {}", e),
    };

    let mut s = String::new();
    match f.read_to_string(&mut s) {
        Ok(_) => f,
        Err(e) => panic!("Could not read config file: {}", e),
    };

    let config: Config = match serde_yaml::from_str(&s) {
        Ok(c) => c,
        Err(e) => panic!("Could not parse config file: {}", e),
    };

    config
}

// Same, but completely without macros
pub fn get_config_lazy(path: String) -> &'static Config {
    static INSTANCE: OnceCell<Config> = OnceCell::new();
    INSTANCE.get_or_init(|| get_config(path))
}
