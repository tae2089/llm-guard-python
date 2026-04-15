use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct Config {
    pub patterns: HashMap<String, PatternEntry>,
}

#[derive(Deserialize)]
pub struct PatternEntry {
    pub name: String,
    pub regex: String,
}
