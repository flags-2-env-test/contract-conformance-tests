mod contract;
mod contract_tree;

use std::path::PathBuf;

pub use contract_tree::audit_contract_tree;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractAuditOptions {
    pub typespec: PathBuf,
    pub schema: PathBuf,
    pub report: PathBuf,
    pub validator: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTreeAuditOptions {
    pub path: PathBuf,
    pub report_root: PathBuf,
    pub validator: String,
}
