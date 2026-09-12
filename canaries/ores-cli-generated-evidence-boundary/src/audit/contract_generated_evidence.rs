use std::fs;
use std::io;
use std::path::{Component, Path};

use serde_json::json;
use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONTRACTS_DIRECTORY: &str = "contracts";
const MAX_WALK_DEPTH: usize = 20;
const MAX_FILES: usize = 4096;
const AUTHORED_TYPESPEC: &str = "main.tsp";
const AUTHORED_JSON_SCHEMA: &str = "authored.schema.json";
const GENERATED_SCHEMA: &str = "generated.schema.json";
const CONTRACT_IR: &str = "contract-ir.json";
const TJSV_REPORT: &str = "tjsv-report.json";
const PARITY_REPORT: &str = "parity-report.json";

const EVIDENCE_DIRECTORIES: [&str; 5] = [
    ".typespec-json-schema-validator",
    "evidence",
    "generated",
    "out",
    "tmp",
];

/// Enforce a filesystem boundary between editable authorities and generated TJSV evidence.
///
/// This audit is deliberately structural. It never decides semantic equivalence and never
/// promotes generated JSON Schema into an authority. TypeSpec and independently authored
/// Draft 2020-12 JSON Schema remain peer sources; canonical TJSV must transpile TypeSpec to
/// comparison-only JSON Schema B and compare B with authored JSON Schema A.
pub(super) fn augment_contract_generated_evidence_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let contracts_root = options.path.join(CONTRACTS_DIRECTORY);
    let metadata = match fs::symlink_metadata(&contracts_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(_) => return report.finalize(),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return report.finalize();
    }

    let mut inspected = 0usize;
    let mut authored_sources = 0usize;
    let mut generated_evidence = 0usize;
    let mut overflow_reported = false;

    let walker = WalkDir::new(&contracts_root)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend);

    for result in walker {
        let Ok(entry) = result else {
            continue;
        };
        if entry.depth() == 0 || !entry.file_type().is_file() {
            continue;
        }
        if inspected >= MAX_FILES {
            if !overflow_reported {
                report.push(
                    Finding::error(
                        "contract-evidence-file-limit",
                        format!(
                            "contracts tree exceeds the {MAX_FILES}-file generated-evidence audit bound"
                        ),
                    )
                    .with_target(CONTRACTS_DIRECTORY),
                );
                overflow_reported = true;
            }
            break;
        }
        inspected += 1;

        let path = entry.path();
        let relative = path.strip_prefix(&options.path).unwrap_or(path);
        let name = entry.file_name().to_string_lossy();
        let in_evidence_directory = has_evidence_directory(relative);
        let target = relative_display(&options.path, path);

        if name == AUTHORED_TYPESPEC || name == AUTHORED_JSON_SCHEMA {
            authored_sources += 1;
            if in_evidence_directory {
                report.push(
                    Finding::error(
                        "authored-contract-source-in-generated-evidence",
                        format!(
                            "{name} is an editable authority and must not live under a generated/evidence directory"
                        ),
                    )
                    .with_target(target),
                );
            }
            continue;
        }

        if is_generated_evidence_name(&name) {
            generated_evidence += 1;
            if !in_evidence_directory {
                report.push(
                    Finding::error(
                        "generated-contract-evidence-in-authority-tree",
                        format!(
                            "{name} is generated comparison evidence and must be isolated under a generated/evidence directory"
                        ),
                    )
                    .with_target(target),
                );
            }
        }
    }

    report.insert_metadata("contractEvidenceFilesInspected", json!(inspected));
    report.insert_metadata("contractAuthoredSourceCount", json!(authored_sources));
    report.insert_metadata("contractGeneratedEvidenceCount", json!(generated_evidence));
    if authored_sources > 0 || generated_evidence > 0 {
        report.push(
            Finding::info(
                "contract-authority-evidence-boundary-inspected",
                format!(
                    "inspected {authored_sources} authored contract sources and {generated_evidence} generated evidence files"
                ),
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
    }
    report.finalize()
}

fn is_generated_evidence_name(name: &str) -> bool {
    matches!(
        name,
        GENERATED_SCHEMA | CONTRACT_IR | TJSV_REPORT | PARITY_REPORT
    ) || name.ends_with(".sarif")
}

fn has_evidence_directory(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(segment) => {
            let segment = segment.to_string_lossy();
            EVIDENCE_DIRECTORIES.contains(&segment.as_ref())
        }
        _ => false,
    })
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(name.as_ref(), ".git" | "target" | "node_modules" | ".dart_tool")
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value as JsonValue;
    use tempfile::tempdir;

    use super::augment_contract_generated_evidence_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        augment_contract_generated_evidence_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn write_authorities(root: &std::path::Path, relative: &str) {
        let directory = root.join(relative);
        fs::create_dir_all(&directory).expect("contract directory");
        fs::write(
            directory.join("main.tsp"),
            "namespace Example;\nmodel Packet { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            directory.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("JSON Schema authority");
    }

    #[test]
    fn accepts_independent_authored_sources_without_generated_evidence() {
        let report = audit(|root| write_authorities(root, "contracts/example"));
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("contractAuthoredSourceCount"),
            Some(&JsonValue::from(2))
        );
    }

    #[test]
    fn rejects_generated_schema_b_beside_authored_authorities() {
        let report = audit(|root| {
            write_authorities(root, "contracts/example");
            fs::write(
                root.join("contracts/example/generated.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("generated evidence");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "generated-contract-evidence-in-authority-tree"
        }));
    }

    #[test]
    fn accepts_generated_schema_b_under_generated_evidence_directory() {
        let report = audit(|root| {
            write_authorities(root, "contracts/example");
            let evidence = root.join("contracts/example/generated");
            fs::create_dir_all(&evidence).expect("generated directory");
            fs::write(
                evidence.join("generated.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("generated schema B");
            fs::write(evidence.join("contract-ir.json"), "{}\n").expect("Contract IR");
            fs::write(evidence.join("report.sarif"), "{}\n").expect("SARIF evidence");
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("contractGeneratedEvidenceCount"),
            Some(&JsonValue::from(3))
        );
    }

    #[test]
    fn rejects_authored_json_schema_inside_generated_directory() {
        let report = audit(|root| {
            let generated = root.join("contracts/example/generated");
            fs::create_dir_all(&generated).expect("generated directory");
            fs::write(
                generated.join("authored.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("misplaced authored authority");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "authored-contract-source-in-generated-evidence"
        }));
    }

    #[test]
    fn rejects_typespec_authority_inside_tjsv_private_evidence_directory() {
        let report = audit(|root| {
            let evidence = root.join("contracts/example/.typespec-json-schema-validator");
            fs::create_dir_all(&evidence).expect("TJSV evidence directory");
            fs::write(
                evidence.join("main.tsp"),
                "namespace Wrong; model Packet {}\n",
            )
            .expect("misplaced TypeSpec authority");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "authored-contract-source-in-generated-evidence"
        }));
    }
}