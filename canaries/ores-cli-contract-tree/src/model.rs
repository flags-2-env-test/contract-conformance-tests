use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable JSON schema identifier for command reports.
pub const REPORT_SCHEMA: &str = "ores.cli.report/v1";

/// Finding severity.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational evidence that does not affect the process exit code.
    Info,
    /// A policy or completeness concern.
    Warning,
    /// A violated required invariant.
    Error,
}

impl Severity {
    /// Whether this severity contributes to the non-zero policy exit code.
    #[must_use]
    pub const fn is_issue(self) -> bool {
        !matches!(self, Self::Info)
    }

    pub(crate) const fn sort_rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
            Self::Info => 2,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        })
    }
}

/// One actionable audit result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable machine-readable code.
    pub code: String,
    /// Severity used for policy exit-code calculation.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
    /// Repository, file, organization, or other target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Additional structured evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl Finding {
    /// Create an informational finding.
    #[must_use]
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    /// Create a warning finding.
    #[must_use]
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    /// Create an error finding.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            target: None,
            details: BTreeMap::new(),
        }
    }

    /// Attach a target identifier.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Attach one JSON-serializable detail.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}

/// Overall report status.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// No warning- or error-level findings.
    Passed,
    /// At least one policy finding requires evaluation.
    StoppedForEvaluation,
}

impl fmt::Display for ReportStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Passed => "passed",
            Self::StoppedForEvaluation => "stopped_for_evaluation",
        })
    }
}

/// Complete result of one command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandReport {
    /// Report contract identifier.
    pub schema: String,
    /// Canonical command path.
    pub command: String,
    /// Overall status.
    pub status: ReportStatus,
    /// Stable ordered findings.
    pub findings: Vec<Finding>,
    /// Command-level structured evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

impl CommandReport {
    /// Create an empty passed report.
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            schema: REPORT_SCHEMA.to_owned(),
            command: command.into(),
            status: ReportStatus::Passed,
            findings: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add a finding.
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add metadata.
    pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
        self.metadata.insert(key.into(), value);
    }

    /// Number of warning- and error-level findings.
    #[must_use]
    pub fn issue_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity.is_issue())
            .count()
    }

    /// Stable process exit code: 0 for pass, 2 for policy findings.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.issue_count() == 0 { 0 } else { 2 }
    }

    /// Finalize status and deterministic finding order.
    #[must_use]
    pub fn finalize(mut self) -> Self {
        self.findings.sort_by(|left, right| {
            left.severity
                .sort_rank()
                .cmp(&right.severity.sort_rank())
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.message.cmp(&right.message))
        });
        self.status = if self.issue_count() == 0 {
            ReportStatus::Passed
        } else {
            ReportStatus::StoppedForEvaluation
        };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandReport, Finding, ReportStatus};

    #[test]
    fn information_does_not_fail_report() {
        let mut report = CommandReport::new("doctor");
        report.push(Finding::info("ready", "ready"));
        let report = report.finalize();
        assert_eq!(report.status, ReportStatus::Passed);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn warnings_stop_for_evaluation() {
        let mut report = CommandReport::new("audit repository");
        report.push(Finding::warning("missing", "missing"));
        let report = report.finalize();
        assert_eq!(report.status, ReportStatus::StoppedForEvaluation);
        assert_eq!(report.exit_code(), 2);
    }
}
