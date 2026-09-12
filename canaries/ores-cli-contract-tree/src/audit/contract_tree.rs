use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;
use walkdir::{DirEntry, WalkDir};

use super::{ContractAuditOptions, ContractTreeAuditOptions};
use crate::error::RuntimeError;
use crate::model::{CommandReport, Finding};

const CONTRACTS_DIRECTORY: &str = "contracts";
const TYPESPEC_FILE: &str = "main.tsp";
const JSON_SCHEMA_FILE: &str = "authored.schema.json";
const TYPESPEC_DIRECTORY: &str = "typespec";
const JSON_SCHEMA_DIRECTORY: &str = "json-schema";
const GENERATED_TYPESPEC_SCHEMA_FILE: &str = "typespec.generated.schema.json";
const GENERATED_SCHEMA_FILE: &str = "generated.schema.json";
const MAX_CONTRACT_DIRECTORIES: usize = 256;
const MAX_WALK_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityKind {
    TypeSpec,
    JsonSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerAuthorityPair {
    directory: PathBuf,
    typespec: PathBuf,
    schema: PathBuf,
}

#[derive(Debug, Default)]
struct CandidateDirectory {
    typespec: Option<PathBuf>,
    schema: Option<PathBuf>,
}

/// Execute compiler-backed TJSV parity for every nested peer-authority pair
/// below `contracts/` and return a standalone command report.
pub async fn audit_contract_tree(
    options: &ContractTreeAuditOptions,
) -> Result<CommandReport, RuntimeError> {
    augment_contract_tree(options, CommandReport::new("audit contract-tree")).await
}

/// Add compiler-backed whole-tree parity evidence to an existing report.
///
/// TypeSpec and the authored Draft 2020-12 JSON Schema remain independent peer
/// authorities. `audit_contract` transpiles TypeSpec to JSON Schema as derived
/// comparison evidence and asks TJSV to compare that generated schema with the
/// independently authored JSON Schema. Generated output is never promoted to a
/// third authored authority.
pub async fn augment_contract_tree(
    options: &ContractTreeAuditOptions,
    mut report: CommandReport,
) -> Result<CommandReport, RuntimeError> {
    let pairs = match discover_peer_authority_pairs(&options.path) {
        Ok(pairs) => pairs,
        Err(finding) => {
            report.push(finding);
            return Ok(report.finalize());
        }
    };

    report.insert_metadata(
        "contractTreePath",
        json!(options.path.to_string_lossy().into_owned()),
    );
    report.insert_metadata("contractTreeValidator", json!(&options.validator));

    if pairs.is_empty() {
        report.push(
            Finding::error(
                "contract-tree-empty",
                "contract-tree audit requires at least one complete TypeSpec/JSON Schema peer-authority pair below contracts/",
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
        return Ok(report.finalize());
    }

    let total = pairs.len();
    let mut receipts = Vec::with_capacity(total);
    let mut passed = 0usize;

    for pair in pairs {
        let relative_directory = pair
            .directory
            .strip_prefix(&options.path)
            .unwrap_or(&pair.directory)
            .to_path_buf();
        let evidence_relative = relative_directory
            .strip_prefix(CONTRACTS_DIRECTORY)
            .unwrap_or(&relative_directory);
        let parity_options = ContractAuditOptions {
            typespec: pair.typespec.clone(),
            schema: pair.schema.clone(),
            report: options
                .report_root
                .join(evidence_relative)
                .join("report.json"),
            validator: options.validator.clone(),
        };

        let parity = super::contract::audit_contract(&parity_options).await?;
        let issues = parity.issue_count();
        if issues == 0 {
            passed += 1;
        }
        receipts.push(json!({
            "directory": relative_display(&options.path, &pair.directory),
            "typespec": relative_display(&options.path, &pair.typespec),
            "authoredJsonSchema": relative_display(&options.path, &pair.schema),
            "report": relative_display(&options.path, &parity_options.report),
            "status": parity.status.to_string(),
            "issueCount": issues,
        }));
        report.findings.extend(parity.findings);
    }

    report.insert_metadata("contractTreeCount", json!(total));
    report.insert_metadata("contractTreePassedCount", json!(passed));
    report.insert_metadata("contractTreeContracts", json!(receipts));

    if passed == total {
        report.push(
            Finding::info(
                "contract-tree-tjsv-passed",
                "all discovered TypeSpec and independently authored JSON Schema pairs passed compiler-backed TypeSpec transpilation, generated-vs-authored schema comparison, and TJSV admission",
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
    }

    Ok(report.finalize())
}

fn discover_peer_authority_pairs(root: &Path) -> Result<Vec<PeerAuthorityPair>, Finding> {
    let contracts = root.join(CONTRACTS_DIRECTORY);
    let metadata = match fs::symlink_metadata(&contracts) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Finding::error(
                "contract-tree-root-unreadable",
                format!("contracts root metadata could not be read: {error}"),
            )
            .with_target(CONTRACTS_DIRECTORY));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Finding::error(
            "contract-tree-root-invalid",
            "contracts root must be a real directory, not a symlink or other file type",
        )
        .with_target(CONTRACTS_DIRECTORY));
    }

    let mut candidates = BTreeMap::<PathBuf, CandidateDirectory>::new();
    let walker = WalkDir::new(&contracts)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend);

    for result in walker {
        let entry = result.map_err(|error| {
            Finding::error(
                "contract-tree-walk-failed",
                format!("contract tree walk failed: {error}"),
            )
            .with_target(error.path().map_or_else(
                || CONTRACTS_DIRECTORY.to_owned(),
                |path| relative_display(root, path),
            ))
        })?;

        let Some((home, kind)) = classify_authority_path(&contracts, entry.path()) else {
            continue;
        };

        if candidates.len() >= MAX_CONTRACT_DIRECTORIES && !candidates.contains_key(&home) {
            return Err(Finding::error(
                "contract-tree-limit",
                format!(
                    "more than {MAX_CONTRACT_DIRECTORIES} contract directories were discovered"
                ),
            )
            .with_target(CONTRACTS_DIRECTORY));
        }

        let candidate = candidates.entry(home.clone()).or_default();
        let slot = match kind {
            AuthorityKind::TypeSpec => &mut candidate.typespec,
            AuthorityKind::JsonSchema => &mut candidate.schema,
        };
        if let Some(existing) = slot.as_ref() {
            if existing != entry.path() {
                return Err(
                    Finding::error(
                        "contract-tree-authority-ambiguous",
                        "contract home contains more than one candidate for the same authored authority lane",
                    )
                    .with_target(relative_display(root, &home)),
                );
            }
        } else {
            *slot = Some(entry.path().to_path_buf());
        }
    }

    let mut pairs = Vec::new();
    for (directory, candidate) in candidates {
        let (typespec, schema) = match (candidate.typespec, candidate.schema) {
            (Some(typespec), Some(schema)) => (typespec, schema),
            (Some(_), None) => {
                return Err(Finding::error(
                    "contract-tree-authored-json-schema-missing",
                    "TypeSpec authority exists without an independent authored JSON Schema peer",
                )
                .with_target(relative_display(root, &directory)));
            }
            (None, Some(_)) => {
                return Err(Finding::error(
                    "contract-tree-typespec-missing",
                    "authored JSON Schema authority exists without an independent TypeSpec peer",
                )
                .with_target(relative_display(root, &directory)));
            }
            (None, None) => continue,
        };
        if !regular_file(&typespec) || !regular_file(&schema) {
            return Err(Finding::error(
                "contract-tree-authority-not-regular",
                "TypeSpec and JSON Schema authorities must both be regular non-symlink files",
            )
            .with_target(relative_display(root, &directory)));
        }
        pairs.push(PeerAuthorityPair {
            directory,
            typespec,
            schema,
        });
    }
    pairs.sort_by(|left, right| left.directory.cmp(&right.directory));
    Ok(pairs)
}

/// Map both supported repository layouts to one logical contract home:
///
/// 1. `contracts/<name>/{main.tsp,authored.schema.json}`
/// 2. `contracts/<name>/typespec/main.tsp` plus exactly one independently
///    authored `contracts/<name>/json-schema/*.schema.json` file.
///
/// The split form is already used by Messaging Intel and Claritas interfaces.
/// Generated TypeSpec JSON Schema witnesses are deliberately not recognized as
/// authored candidates. Multiple authored `*.schema.json` candidates fail
/// closed as ambiguous rather than making filename precedence a hidden policy.
fn classify_authority_path(contracts: &Path, path: &Path) -> Option<(PathBuf, AuthorityKind)> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent()?;
    let parent_name = parent.file_name().and_then(|value| value.to_str());

    if name == TYPESPEC_FILE {
        let home = if parent_name == Some(TYPESPEC_DIRECTORY) {
            parent.parent()?.to_path_buf()
        } else {
            parent.to_path_buf()
        };
        return home
            .starts_with(contracts)
            .then_some((home, AuthorityKind::TypeSpec));
    }

    let direct_authored = name == JSON_SCHEMA_FILE && parent_name != Some(JSON_SCHEMA_DIRECTORY);
    let split_authored = parent_name == Some(JSON_SCHEMA_DIRECTORY)
        && name.ends_with(".schema.json")
        && !is_generated_schema_witness(name);
    if direct_authored || split_authored {
        let home = if split_authored {
            parent.parent()?.to_path_buf()
        } else {
            parent.to_path_buf()
        };
        return home
            .starts_with(contracts)
            .then_some((home, AuthorityKind::JsonSchema));
    }

    None
}

fn is_generated_schema_witness(name: &str) -> bool {
    name == GENERATED_TYPESPEC_SCHEMA_FILE
        || name == GENERATED_SCHEMA_FILE
        || name.ends_with(".generated.schema.json")
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(
        name.as_ref(),
        ".git"
            | "target"
            | "node_modules"
            | ".dart_tool"
            | ".typespec-json-schema-validator"
            | "generated"
    )
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
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
    use std::path::Path;

    use tempfile::tempdir;

    use super::discover_peer_authority_pairs;

    fn write_direct_pair(root: &Path, relative: &str) {
        let directory = root.join(relative);
        fs::create_dir_all(&directory).expect("contract directory");
        fs::write(
            directory.join("main.tsp"),
            "namespace Example; model Payload { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            directory.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("JSON Schema authority");
    }

    fn write_split_pair(root: &Path, relative: &str, schema_name: &str) {
        let directory = root.join(relative);
        fs::create_dir_all(directory.join("typespec")).expect("TypeSpec directory");
        fs::create_dir_all(directory.join("json-schema")).expect("JSON Schema directory");
        fs::write(
            directory.join("typespec/main.tsp"),
            "namespace Example; model Payload { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            directory.join("json-schema").join(schema_name),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("JSON Schema authority");
    }

    #[test]
    fn discovers_multiple_nested_peer_pairs_in_stable_order() {
        let root = tempdir().expect("temporary repository");
        write_direct_pair(root.path(), "contracts/zeta");
        write_direct_pair(root.path(), "contracts/alpha/v1");
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 2);
        assert!(pairs[0].directory.ends_with("contracts/alpha/v1"));
        assert!(pairs[1].directory.ends_with("contracts/zeta"));
    }

    #[test]
    fn discovers_split_peer_authority_layout_used_by_messaging_intel() {
        let root = tempdir().expect("temporary repository");
        write_split_pair(
            root.path(),
            "contracts/claritas-viz",
            "contract.schema.json",
        );
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].directory.ends_with("contracts/claritas-viz"));
        assert!(
            pairs[0]
                .typespec
                .ends_with("contracts/claritas-viz/typespec/main.tsp")
        );
        assert!(
            pairs[0]
                .schema
                .ends_with("contracts/claritas-viz/json-schema/contract.schema.json")
        );
    }

    #[test]
    fn discovers_named_split_schema_used_by_claritas_interfaces() {
        let root = tempdir().expect("temporary repository");
        write_split_pair(root.path(), "contracts/renderer", "network.schema.json");
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].directory.ends_with("contracts/renderer"));
        assert!(
            pairs[0]
                .schema
                .ends_with("contracts/renderer/json-schema/network.schema.json")
        );
    }

    #[test]
    fn split_layout_accepts_canonical_authored_schema_name() {
        let root = tempdir().expect("temporary repository");
        write_split_pair(
            root.path(),
            "contracts/participant-metrics",
            "authored.schema.json",
        );
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 1);
        assert!(
            pairs[0]
                .schema
                .ends_with("contracts/participant-metrics/json-schema/authored.schema.json")
        );
    }

    #[test]
    fn mixed_direct_and_split_layouts_share_one_bounded_audit() {
        let root = tempdir().expect("temporary repository");
        write_direct_pair(root.path(), "contracts/direct");
        write_split_pair(root.path(), "contracts/split", "contract.schema.json");
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 2);
        assert!(pairs[0].directory.ends_with("contracts/direct"));
        assert!(pairs[1].directory.ends_with("contracts/split"));
    }

    #[test]
    fn ignores_generated_contract_witnesses() {
        let root = tempdir().expect("temporary repository");
        write_direct_pair(root.path(), "contracts/live");
        write_direct_pair(root.path(), "contracts/generated/derived");
        let pairs = discover_peer_authority_pairs(root.path()).expect("pair discovery");
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].directory.ends_with("contracts/live"));
    }

    #[test]
    fn generated_schema_b_inside_split_home_cannot_become_authored_authority() {
        let root = tempdir().expect("temporary repository");
        let directory = root.path().join("contracts/renderer");
        fs::create_dir_all(directory.join("typespec")).expect("TypeSpec directory");
        fs::create_dir_all(directory.join("json-schema")).expect("JSON Schema directory");
        fs::write(directory.join("typespec/main.tsp"), "model Half {}\n").expect("TypeSpec");
        fs::write(
            directory.join("json-schema/typespec.generated.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("generated witness");

        let error = discover_peer_authority_pairs(root.path())
            .expect_err("generated Schema B must not satisfy the authored JSON lane");
        assert_eq!(error.code, "contract-tree-authored-json-schema-missing");
    }

    #[test]
    fn incomplete_pairs_fail_closed() {
        let root = tempdir().expect("temporary repository");
        let directory = root.path().join("contracts/half");
        fs::create_dir_all(&directory).expect("contract directory");
        fs::write(directory.join("main.tsp"), "model Half {}\n").expect("TypeSpec");
        let error =
            discover_peer_authority_pairs(root.path()).expect_err("one-sided pair must fail");
        assert_eq!(error.code, "contract-tree-authored-json-schema-missing");
    }

    #[test]
    fn split_layout_incomplete_pair_fails_closed() {
        let root = tempdir().expect("temporary repository");
        let directory = root.path().join("contracts/claritas-viz/typespec");
        fs::create_dir_all(&directory).expect("contract directory");
        fs::write(directory.join("main.tsp"), "model Half {}\n").expect("TypeSpec");
        let error =
            discover_peer_authority_pairs(root.path()).expect_err("one-sided pair must fail");
        assert_eq!(error.code, "contract-tree-authored-json-schema-missing");
    }

    #[test]
    fn split_layout_rejects_ambiguous_json_schema_authorities() {
        let root = tempdir().expect("temporary repository");
        write_split_pair(
            root.path(),
            "contracts/claritas-viz",
            "authored.schema.json",
        );
        fs::write(
            root.path()
                .join("contracts/claritas-viz/json-schema/network.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("second JSON Schema authority");
        let error = discover_peer_authority_pairs(root.path())
            .expect_err("ambiguous authority candidates must fail");
        assert_eq!(error.code, "contract-tree-authority-ambiguous");
    }
}
