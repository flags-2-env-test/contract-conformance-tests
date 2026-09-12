#![forbid(unsafe_code)]

//! Reusable SDK behind the `ores-cli` executable.
//!
//! The library owns command dispatch, audit models, GitHub CLI integration, and
//! stdout rendering. `src/main.rs` contains only process exit/error handling.

/// Audit implementations and option models.
pub mod audit;
/// Process-level runtime and usage errors.
pub mod error;
/// flags-2-env parsing and typed command resolution.
pub mod flags;
/// Authenticated GitHub CLI subprocess gateway.
pub mod github;
/// Stable findings and command-report models.
pub mod model;
/// GitHub organization inspection and repository-management commands.
pub mod org;
/// Multi-organization discovery, interactive selection, and streamed reconciliation.
pub mod orgs;
/// JSON, plain, and shell-composable stdout renderers.
pub mod output;
/// Read-only repository standards and offline CLI-name admission planning.
pub mod standards;

mod process;
mod python_systems;

use std::time::Duration;

use next_loggers::SCHEMA as ORES_OTEL_SCHEMA;
use serde_json::json;
use tokio::process::Command;

use crate::audit::{
    ContractAuditOptions, ContractTreeAuditOptions, RepositoryAuditOptions, audit_contract,
    audit_contract_tree, audit_github_org, audit_package, audit_repository,
};
use crate::error::RuntimeError;
use crate::flags::{CliCommand, CliInvocation, active_flag_contract_path, parse_invocation};
use crate::github::GhCli;
use crate::model::{CommandReport, Finding};
use crate::org::{create_missing_repositories, inspect_github_org, list_missing_repositories};
use crate::output::{emit_report, emit_repository_names};
use crate::process::{CaptureLimits, run_bounded};

/// Parse the current process, execute one command, and emit its report.
pub async fn run_process() -> Result<u8, RuntimeError> {
    let argv = std::env::args().collect::<Vec<_>>();
    let invocation = parse_invocation(&argv)?;
    let json_output = invocation.json;
    let result = run_invocation(invocation).await;
    if let Err(error) = &result
        && let Some(report) = error.partial_report()
    {
        // Receipts are command evidence, not optional progress.
        emit_report(report, json_output)?;
    }
    result
}

async fn run_invocation(invocation: CliInvocation) -> Result<u8, RuntimeError> {
    if let CliCommand::Organizations(options) = &invocation.command {
        return orgs::run_process(options, invocation.json).await;
    }
    let repository_name_output = invocation.command.emits_repository_names();
    let json_output = invocation.json;
    let report = execute(invocation).await?;
    let exit_code = report.exit_code();
    if repository_name_output {
        emit_repository_names(&report)?;
    } else {
        emit_report(&report, json_output)?;
    }
    Ok(exit_code)
}

/// Execute a resolved invocation without writing output.
///
/// SDK consumers can inspect or render the returned report themselves.
pub async fn execute(invocation: CliInvocation) -> Result<CommandReport, RuntimeError> {
    match invocation.command {
        CliCommand::Doctor => doctor().await,
        CliCommand::Organizations(options) => orgs::execute(&options).await,
        CliCommand::Org(scope) => {
            let gh = GhCli::new();
            inspect_github_org(&gh, &scope).await
        }
        CliCommand::OrgListMissing(options) => {
            let gh = GhCli::new();
            list_missing_repositories(&gh, &options).await
        }
        CliCommand::OrgCreateMissing(options) => {
            let gh = GhCli::new();
            create_missing_repositories(&gh, &options).await
        }
        CliCommand::AuditOrg(options) => {
            let gh = GhCli::new();
            audit_github_org(&gh, &options).await
        }
        CliCommand::AuditRepository(options) if options.profile == "infra" => {
            let root = options.path.clone();
            let report = audit_infra_repository(&options).await?;
            Ok(python_systems::audit(&root, report))
        }
        CliCommand::AuditRepository(options) if options.profile == "interfaces" => {
            let root = options.path.clone();
            let report = audit_interfaces_repository(&options).await?;
            Ok(python_systems::audit(&root, report))
        }
        CliCommand::AuditRepository(options)
            if matches!(options.profile.as_str(), "standards" | "standards-logs") =>
        {
            let root = options.path.clone();
            let request = standards::StandardsOptions {
                path: options.path,
                scan_logs: options.profile == "standards-logs",
                additional_required_paths: options.additional_required_paths,
            };
            let report = standards::audit_standards(&request).await;
            Ok(python_systems::audit(&root, report))
        }
        CliCommand::AuditRepository(options) => {
            let root = options.path.clone();
            let report = audit_repository(&options);
            Ok(python_systems::audit(&root, report))
        }
        CliCommand::AuditPackage(options) => Ok(audit_package(&options)),
        CliCommand::AuditContract(options) => audit_contract(&options).await,
    }
}

async fn audit_interfaces_repository(
    options: &RepositoryAuditOptions,
) -> Result<CommandReport, RuntimeError> {
    let mut report = audit_repository(options);
    let tree_options = ContractTreeAuditOptions {
        path: options.path.clone(),
        report_root: options
            .path
            .join(".typespec-json-schema-validator/contract-tree"),
        validator: "tjsv".to_owned(),
    };
    let parity = audit_contract_tree(&tree_options).await?;
    report.findings.extend(parity.findings);
    report.insert_metadata("interfacesTjsv", json!(parity.metadata));
    Ok(report.finalize())
}

async fn audit_infra_repository(
    options: &RepositoryAuditOptions,
) -> Result<CommandReport, RuntimeError> {
    let mut report = audit_repository(options);
    let contract_root = options.path.join("contracts/infra-gitops");
    let contract_options = ContractAuditOptions {
        typespec: contract_root.join("main.tsp"),
        schema: contract_root.join("authored.schema.json"),
        report: options
            .path
            .join(".typespec-json-schema-validator/infra-gitops/report.json"),
        validator: "tjsv".to_owned(),
    };

    // The infra profile intentionally makes TJSV a required runtime dependency.
    // Structural findings and parity findings are independent evidence, so run
    // both lanes rather than allowing one failure class to mask the other.
    let parity = audit_contract(&contract_options).await?;
    report.findings.extend(parity.findings);
    report.insert_metadata("infraTjsv", json!(parity.metadata));
    report.push(
        Finding::info(
            "infra-tjsv-executed",
            "infra profile executed canonical tjsv against the independent provider contract authorities",
        )
        .with_target("contracts/infra-gitops"),
    );

    Ok(report.finalize())
}

async fn doctor() -> Result<CommandReport, RuntimeError> {
    let mut report = CommandReport::new("doctor");
    let descriptor = ores_middleware::descriptor();
    let flag_contract = active_flag_contract_path()?;

    report.insert_metadata("flagContract", json!(&flag_contract));
    report.insert_metadata("otelSchema", json!(ORES_OTEL_SCHEMA));
    report.insert_metadata("middlewarePackage", json!(descriptor.package_name));
    report.insert_metadata(
        "middlewareContractVersion",
        json!(descriptor.contract_version),
    );
    report.insert_metadata("middlewareCapabilities", json!(descriptor.capabilities));
    report.insert_metadata(
        "rateLimitAuthority",
        json!("ores-rate-limit/ores-rl-lib-core via zed-pkg"),
    );

    report.push(Finding::info(
        "flag-contract-valid",
        format!("flags-2-env audited `{flag_contract}` before command dispatch"),
    ));
    report.push(Finding::info(
        "ores-otel-ready",
        format!("structured stdout uses {ORES_OTEL_SCHEMA}"),
    ));
    report.push(Finding::info(
        "ores-middleware-ready",
        "GitHub subprocess requests use the ores-middleware bounded token bucket",
    ));
    report.push(Finding::info(
        "rate-limit-package-tracked",
        "the canonical rate-limit core is declared in .zpkg.toml",
    ));

    record_program(&mut report, "gh", &["--version"], true).await;
    record_program(&mut report, "tjsv", &["--version"], false).await;

    Ok(report.finalize())
}

async fn record_program(report: &mut CommandReport, program: &str, args: &[&str], required: bool) {
    let mut command = Command::new(program);
    command.args(args);
    let result = run_bounded(
        command,
        format!("{program} version probe"),
        CaptureLimits::new(Duration::from_secs(10), 64 * 1024, 64 * 1024),
    )
    .await;

    match result {
        Ok(output) if output.status.success() => {
            let version = output.stdout.lines().next().unwrap_or_default().trim();
            report.push(
                Finding::info(
                    format!("{program}-available"),
                    format!("`{program}` is available"),
                )
                .with_target(program.to_owned())
                .with_detail("version", json!(version)),
            );
        }
        Ok(output) => {
            let diagnostic = if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            };
            let code = format!("{program}-unavailable");
            let message = format!(
                "`{program}` returned exit code {:?}: {}",
                output.status.code(),
                truncate(diagnostic)
            );
            let finding = if required {
                Finding::warning(code, message)
            } else {
                Finding::info(code, message)
            };
            report.push(
                finding
                    .with_target(program.to_owned())
                    .with_detail("requiredForDefaultAudit", json!(required)),
            );
        }
        Err(error) => {
            let code = format!("{program}-unavailable");
            let message = format!("`{program}` probe failed: {error}");
            let finding = if required {
                Finding::warning(code, message)
            } else {
                Finding::info(code, message)
            };
            report.push(
                finding
                    .with_target(program.to_owned())
                    .with_detail("requiredForDefaultAudit", json!(required)),
            );
        }
    }
}

fn truncate(value: &str) -> String {
    const LIMIT: usize = 1_024;
    if value.len() <= LIMIT {
        return value.to_owned();
    }
    let mut boundary = LIMIT;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}…", &value[..boundary])
}
