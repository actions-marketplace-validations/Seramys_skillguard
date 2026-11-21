use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub ignore_rules: Vec<String>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub max_file_size_kb: Option<u64>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub rules_dir: Option<String>,
    #[serde(default)]
    pub semantic: crate::semantic::SemanticConfig,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid config {}: {e}", path.display()))
}

pub fn discover(root: &Path) -> Option<PathBuf> {
    let local = if root.is_dir() {
        root.join(".skillguard.json")
    } else {
        root.parent()?.join(".skillguard.json")
    };
    if local.is_file() {
        return Some(local);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(".skillguard.json");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_partial_config() {
        let cfg: Config = serde_json::from_str(r#"{"fail_on":"high","exclude":["dist"]}"#).unwrap();
        assert_eq!(cfg.fail_on.as_deref(), Some("high"));
        assert_eq!(cfg.exclude, vec!["dist"]);
        assert!(cfg.allow_domains.is_empty());
    }
}
