pub mod model {
    use std::collections::BTreeMap;

    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Finding {
        pub code: String,
        pub severity: Severity,
        pub message: String,
        pub target: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Severity {
        Error,
        Info,
    }

    impl Finding {
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                severity: Severity::Error,
                message: message.into(),
                target: None,
            }
        }

        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                severity: Severity::Info,
                message: message.into(),
                target: None,
            }
        }

        #[must_use]
        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
            self
        }
    }

    #[derive(Debug, Clone)]
    pub struct CommandReport {
        pub command: String,
        pub findings: Vec<Finding>,
        pub metadata: BTreeMap<String, Value>,
    }

    impl CommandReport {
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command: command.into(),
                findings: Vec::new(),
                metadata: BTreeMap::new(),
            }
        }

        pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
            self.metadata.insert(key.into(), value);
        }

        pub fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
        }

        #[must_use]
        pub fn finalize(self) -> Self {
            self
        }

        #[must_use]
        pub fn issue_count(&self) -> usize {
            self.findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .count()
        }
    }
}

pub mod audit {
    use std::path::{Path, PathBuf};

    use crate::model::CommandReport;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    mod contract_generated_evidence;

    #[must_use]
    pub fn run_generated_evidence_boundary(path: &Path) -> CommandReport {
        contract_generated_evidence::augment_contract_generated_evidence_audit(
            &RepositoryAuditOptions {
                path: path.to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }
}
