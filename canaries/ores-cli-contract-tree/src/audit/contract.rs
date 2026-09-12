use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tokio::process::Command;

use super::ContractAuditOptions;
use crate::error::RuntimeError;
use crate::model::{CommandReport, Finding};

const GENERATED_BUNDLE_ID: &str = "typespec.generated.schema.json";

pub async fn audit_contract(options: &ContractAuditOptions) -> Result<CommandReport, RuntimeError> {
    let mut report = CommandReport::new("audit contract");
    let parent = options
        .report
        .parent()
        .ok_or_else(|| RuntimeError::Validator("report path has no parent".to_owned()))?;
    let generated = parent.join("generated");
    let sarif = parent.join("report.sarif");
    let contract_ir = parent.join("contract-ir.json");
    fs::create_dir_all(&generated)?;

    let mut command = Command::new(&options.validator);
    command
        .arg("check")
        .arg("--typespec")
        .arg(&options.typespec)
        .arg("--schema")
        .arg(&options.schema)
        .arg("--output-dir")
        .arg(&generated)
        .arg("--bundle-id")
        .arg(GENERATED_BUNDLE_ID)
        .arg("--report")
        .arg(&options.report)
        .arg("--sarif")
        .arg(&sarif)
        .arg("--contract-ir")
        .arg(&contract_ir);
    if let Some(instances) = discover_instances(&options.typespec, &options.schema) {
        command.arg("--instances").arg(instances);
    }
    command.arg("--quiet");

    let output = command.output().await?;
    if !output.status.success() {
        return Err(RuntimeError::Validator(format!(
            "{} check exited {:?}: {}",
            options.validator,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let receipt: Value = serde_json::from_slice(&fs::read(&options.report)?)?;
    let generated_path = generated.join(GENERATED_BUNDLE_ID);
    let generated_schema: Value = serde_json::from_slice(&fs::read(&generated_path)?)?;
    let authorities = &receipt["authorities"];
    let differential = &receipt["differential"]["summary"];
    let passed = receipt["status"] == "passed"
        && receipt["zeroUnexplainedFindings"] == true
        && authorities["precedence"] == "none"
        && authorities["typespec"]["authority"] == "independently-authored"
        && authorities["jsonSchema"]["authority"] == "independently-authored"
        && authorities["typespec"]["generatedJsonSchemaRole"] == "comparison-evidence-only"
        && receipt["coverage"]["typespecGeneratedJsonSchemaComparison"] == true
        && receipt["coverage"]["differentialInstanceValidation"] == true
        && differential["probesEvaluated"].as_u64().unwrap_or_default() > 0
        && differential["divergences"].as_u64().unwrap_or(u64::MAX) == 0
        && differential["refusals"].as_u64().unwrap_or(u64::MAX) == 0
        && generated_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema";

    report.insert_metadata(
        "typespec",
        json!(options.typespec.to_string_lossy().into_owned()),
    );
    report.insert_metadata(
        "authoredJsonSchema",
        json!(options.schema.to_string_lossy().into_owned()),
    );
    report.insert_metadata(
        "generatedJsonSchema",
        json!(generated_path.to_string_lossy().into_owned()),
    );
    report.insert_metadata("validatorReceipt", receipt.clone());

    if passed {
        report.push(
            Finding::info(
                "contract-parity-passed",
                "independent TypeSpec and authored JSON Schema passed official TypeSpec transpilation, generated-Schema-B comparison, and differential TJSV admission",
            )
            .with_target(options.report.to_string_lossy()),
        );
    } else {
        report.push(
            Finding::error(
                "contract-parity-evidence-invalid",
                "TJSV returned zero but did not publish the required peer-authority and generated-Schema-B evidence",
            )
            .with_target(options.report.to_string_lossy()),
        );
    }

    Ok(report.finalize())
}

fn discover_instances(typespec: &Path, schema: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for source in [typespec, schema] {
        if let Some(parent) = source.parent() {
            candidates.push(parent.join("instances"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("instances"));
            }
        }
    }
    candidates.into_iter().find(|path| path.is_dir())
}
