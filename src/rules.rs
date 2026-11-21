use crate::model::Severity;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    SkillMd,
    Markdown,
    Script,
    Config,
    Text,
    Pdf,
    Path,
    All,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub applies_to: Vec<Scope>,
    #[serde(default)]
    pub max_matches: Option<usize>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
}

fn default_true() -> bool {
    true
}

fn default_min_len() -> usize {
    20
}

fn default_entropy() -> f64 {
    4.0
}

fn default_b64_len() -> usize {
    120
}

fn default_padding_min_lines() -> usize {
    2000
}

fn default_padding_ratio() -> f64 {
    0.02
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchSpec {
    Regex {
        pattern: String,
        #[serde(default)]
        absent: Option<String>,
    },
    PathRegex {
        pattern: String,
    },
    SecretEntropy {
        #[serde(default = "default_min_len")]
        min_length: usize,
        #[serde(default = "default_entropy")]
        threshold: f64,
        #[serde(default)]
        prefixes: Vec<String>,
    },
    HiddenUnicode,
    Base64Blob {
        #[serde(default = "default_b64_len")]
        min_length: usize,
    },
    FrontmatterMissing {
        #[serde(default)]
        fields: Vec<String>,
    },
    Combo {
        #[serde(default)]
        groups: Vec<Vec<String>>,
        #[serde(default)]
        none_of: Vec<String>,
    },
    Padding {
        #[serde(default = "default_padding_min_lines")]
        min_lines: usize,
        #[serde(default = "default_padding_ratio")]
        max_nonempty_ratio: f64,
    },
    BytecodeIntegrity,
    ContainerScript {
        #[serde(default)]
        extensions: Vec<String>,
    },
    ContainerOle,
    BytecodeDanger,
    CodeSignal {
        signal: String,
    },
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Option<Regex>,
    pub absent: Option<Regex>,
    pub path_regex: Option<Regex>,
}

impl CompiledRule {
    pub fn compile(rule: Rule) -> Result<Self, String> {
        let mut regex = None;
        let mut absent = None;
        let mut path_regex = None;
        match &rule.matcher {
            MatchSpec::Regex {
                pattern,
                absent: absent_pattern,
            } => {
                regex = Some(
                    Regex::new(pattern)
                        .map_err(|e| format!("rule {} has an invalid regex: {e}", rule.id))?,
                );
                if let Some(p) = absent_pattern {
                    absent = Some(Regex::new(p).map_err(|e| {
                        format!("rule {} has an invalid absent regex: {e}", rule.id)
                    })?);
                }
            }
            MatchSpec::PathRegex { pattern } => {
                path_regex = Some(
                    Regex::new(pattern)
                        .map_err(|e| format!("rule {} has an invalid path regex: {e}", rule.id))?,
                );
            }
            _ => {}
        }
        Ok(Self {
            rule,
            regex,
            absent,
            path_regex,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RulePack {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
    rules: Vec<Rule>,
}

pub fn load_builtin() -> Result<Vec<Rule>, String> {
    let text = include_str!("../rules/core.json");
    let pack: RulePack =
        serde_json::from_str(text).map_err(|e| format!("builtin rule pack is invalid: {e}"))?;
    Ok(pack.rules)
}

pub fn load_file(path: &Path) -> Result<Vec<Rule>, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read rule file {}: {e}", path.display()))?;
    let pack: RulePack = serde_json::from_str(&text)
        .map_err(|e| format!("invalid rule file {}: {e}", path.display()))?;
    Ok(pack.rules)
}

pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, String> {
    let mut paths = Vec::new();
    let entries =
        fs::read_dir(dir).map_err(|e| format!("cannot read rules dir {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        out.extend(load_file(&path)?);
    }
    Ok(out)
}

/// External rules override built-in rules with the same id.
pub fn merge(base: Vec<Rule>, extra: Vec<Rule>) -> (Vec<Rule>, Vec<String>) {
    let mut map: BTreeMap<String, Rule> = BTreeMap::new();
    for rule in base {
        map.insert(rule.id.clone(), rule);
    }
    let mut warnings = Vec::new();
    for rule in extra {
        if map.contains_key(&rule.id) {
            warnings.push(format!("external rule {} overrides built-in rule", rule.id));
        }
        map.insert(rule.id.clone(), rule);
    }
    (map.into_values().collect(), warnings)
}

pub fn compile_all(rules: Vec<Rule>) -> Result<Vec<CompiledRule>, String> {
    rules
        .into_iter()
        .filter(|r| r.enabled)
        .map(CompiledRule::compile)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_pack_compiles() {
        let rules = load_builtin().unwrap();
        assert!(rules.len() >= 20, "expected a useful builtin rule pack");
        let compiled = compile_all(rules).unwrap();
        assert!(compiled.iter().any(|r| r.rule.id == "SG-PI-001"));
        assert!(compiled.iter().any(|r| r.rule.id == "SG-COMBO-001"));
    }

    #[test]
    fn parses_secret_entropy_rule() {
        let rule: Rule = serde_json::from_str(
            r#"{"id":"X","title":"t","severity":"medium","category":"secret","match":{"type":"secret_entropy","min_length":24}}"#,
        )
        .unwrap();
        match rule.matcher {
            MatchSpec::SecretEntropy { min_length, .. } => assert_eq!(min_length, 24),
            _ => panic!("wrong matcher"),
        }
    }
}
