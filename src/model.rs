use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            Self::Low => "note",
            Self::Medium => "warning",
            Self::High | Self::Critical => "error",
        }
    }

    pub fn ansi(self) -> &'static str {
        match self {
            Self::Low => "\x1b[36m",
            Self::Medium => "\x1b[33m",
            Self::High => "\x1b[31m",
            Self::Critical => "\x1b[1;31m",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub skill: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub excerpt: String,
    pub message: String,
    pub remediation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub skill: String,
    pub kind: String,
    pub target: String,
    pub file: String,
    pub line: usize,
    pub declared: bool,
    pub evidence: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Summary {
    pub skills: usize,
    pub files: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

impl Summary {
    pub fn from_findings(skills: usize, files: usize, findings: &[Finding]) -> Self {
        let mut s = Self {
            skills,
            files,
            total: findings.len(),
            ..Self::default()
        };
        for f in findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
            }
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub root: PathBuf,
    pub skill_md: Option<PathBuf>,
    pub files: Vec<PathBuf>,
}
