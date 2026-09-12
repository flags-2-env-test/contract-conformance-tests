use std::path::PathBuf;

use ores_cli::audit::{ContractTreeAuditOptions, audit_contract_tree};
use tempfile::tempdir;
use walkdir::WalkDir;

#[tokio::test]
async fn external_test_org_contract_tree_transpiles_and_matches_authored_schema() {
    let Some(repository) = std::env::var_os("ORES_CLI_TEST_INTERFACE_REPO") else {
        eprintln!("ORES_CLI_TEST_INTERFACE_REPO is unset; skipping external *-test contract tree");
        return;
    };
    let repository = PathBuf::from(repository);
    let evidence = tempdir().expect("temporary parity evidence root");
    let validator = std::env::var("ORES_CLI_TEST_TJSV").unwrap_or_else(|_| "tjsv".to_owned());

    let report = audit_contract_tree(&ContractTreeAuditOptions {
        path: repository,
        report_root: evidence.path().to_path_buf(),
        validator,
    })
    .await
    .expect("contract-tree audit must execute");

    assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    let count = report
        .metadata
        .get("contractTreeCount")
        .and_then(serde_json::Value::as_u64)
        .expect("contract tree count");
    assert!(count > 0, "external test repo must carry peer authorities");
    assert_eq!(
        report
            .metadata
            .get("contractTreePassedCount")
            .and_then(serde_json::Value::as_u64),
        Some(count)
    );

    let generated = WalkDir::new(evidence.path())
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.file_name() == "typespec.generated.schema.json")
        .count();
    assert_eq!(
        generated,
        usize::try_from(count).expect("bounded contract count"),
        "every TypeSpec peer must emit generated JSON Schema comparison evidence"
    );
}
