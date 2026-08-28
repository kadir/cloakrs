use crate::output::sarif::{self, SarifFinding};
use clap::{Args, Parser, Subcommand, ValueEnum};
use cloakrs_adapters::{
    mask_log_reader, scan_csv_str, scan_json_str, scan_log_str, scan_sql_str, scan_text,
    AdapterFinding, AdapterKind, AdapterReport, CsvScanOptions, JsonScanOptions, LogLineScanResult,
};
use cloakrs_core::{EntityType, Locale, MaskStrategy, Scanner};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Command-line interface for cloakrs.
#[derive(Debug, Parser)]
#[command(name = "cloakrs")]
#[command(
    version,
    about = "Detect and mask PII in text, streams, and structured data"
)]
pub struct Cli {
    /// Shared options accepted by every command.
    #[command(flatten)]
    pub global: GlobalOptions,
    /// Operation to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Options shared by all commands.
#[derive(Debug, Clone, Args, PartialEq)]
pub struct GlobalOptions {
    /// Locales to enable, separated by commas.
    #[arg(
        long,
        global = true,
        value_delimiter = ',',
        default_value = "universal"
    )]
    pub locale: Vec<LocaleArg>,
    /// Entity types to exclude, separated by commas.
    #[arg(long, global = true, value_delimiter = ',')]
    pub exclude_entities: Vec<EntityTypeArg>,
    /// Masking strategy to apply.
    #[arg(long, global = true, default_value = "redact")]
    pub strategy: StrategyArg,
    /// Minimum confidence threshold from 0.0 to 1.0.
    #[arg(long, global = true, default_value = "0.5", value_parser = parse_confidence)]
    pub min_confidence: f64,
    /// Report output format.
    #[arg(long, global = true, default_value = "text")]
    pub output_format: OutputFormat,
    /// Suppress stats and write only masked output where supported.
    #[arg(long, global = true)]
    pub quiet: bool,
    /// Path to a cloakrs TOML configuration file.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// Append structured JSONL audit events to this file.
    #[arg(long, global = true)]
    pub audit_log: Option<PathBuf>,
}

/// CLI subcommands.
#[derive(Debug, Clone, Subcommand, PartialEq)]
pub enum Command {
    /// Scan one input file.
    Scan(ScanArgs),
    /// Read logs or text from stdin and write masked output to stdout.
    Stream(StreamArgs),
    /// Recursively scan a directory and produce a compliance report.
    Audit(AuditArgs),
    /// Scan paths passed by the pre-commit framework.
    PreCommit(PreCommitArgs),
}

/// Arguments for `cloakrs scan`.
#[derive(Debug, Clone, Args, PartialEq)]
pub struct ScanArgs {
    /// Path to scan.
    pub path: PathBuf,
    /// Input format override.
    #[arg(long, default_value = "auto")]
    pub format: InputFormat,
    /// Write masked output or report to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// CSV columns to scan, by name or zero-based index.
    #[arg(long, value_delimiter = ',')]
    pub columns: Vec<String>,
    /// JSON paths to scan.
    #[arg(long, value_delimiter = ',')]
    pub include_paths: Vec<String>,
    /// JSON paths to skip.
    #[arg(long, value_delimiter = ',')]
    pub exclude_paths: Vec<String>,
}

/// Arguments for `cloakrs stream`.
#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct StreamArgs {}

/// Arguments for `cloakrs audit`.
#[derive(Debug, Clone, Args, PartialEq)]
pub struct AuditArgs {
    /// Directory to audit.
    pub path: PathBuf,
    /// Recurse into subdirectories.
    #[arg(long, default_value_t = true)]
    pub recursive: bool,
    /// Honor .gitignore files.
    #[arg(long, default_value_t = true)]
    pub respect_gitignore: bool,
    /// Number of worker threads to use.
    #[arg(long)]
    pub parallel: Option<usize>,
    /// Minimum severity to report.
    #[arg(long, default_value = "low")]
    pub severity: SeverityArg,
    /// Write the report to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Arguments for `cloakrs pre-commit`.
#[derive(Debug, Clone, Args, PartialEq)]
pub struct PreCommitArgs {
    /// Files passed by pre-commit.
    pub paths: Vec<PathBuf>,
    /// Minimum severity to report.
    #[arg(long, default_value = "low")]
    pub severity: SeverityArg,
    /// Write the report to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Input file formats supported by `scan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[value(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum InputFormat {
    /// Detect format from file extension.
    Auto,
    /// Plain text.
    Text,
    /// JSON.
    Json,
    /// CSV.
    Csv,
    /// Log stream.
    Log,
    /// SQL dump.
    Sql,
}

/// Report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Human-readable text.
    Text,
    /// Machine-readable JSON.
    Json,
    /// SARIF v2.1.0.
    Sarif,
}

/// Masking strategies accepted by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum StrategyArg {
    /// Replace findings with typed tags like `[EMAIL]`.
    Redact,
    /// Preserve selected characters while masking the middle.
    PartialMask,
    /// Replace findings with deterministic SHA-256 hashes.
    Hash,
    /// Replace findings with deterministic fake-safe values.
    Replace,
    /// Encrypt findings with AES-256-GCM.
    Encrypt,
}

/// Locale selectors accepted by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum LocaleArg {
    /// Universal recognizers.
    Universal,
    /// United States.
    Us,
    /// Netherlands.
    Nl,
    /// United Kingdom.
    Uk,
    /// Germany.
    De,
    /// France.
    Fr,
    /// India.
    In,
    /// Brazil.
    Br,
    /// European Union meta-locale.
    Eu,
}

/// Entity types accepted by `--exclude-entities` and configuration files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[value(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum EntityTypeArg {
    Email,
    PhoneNumber,
    CreditCard,
    Iban,
    IpAddress,
    Url,
    DateOfBirth,
    ApiKey,
    Jwt,
    AwsAccessKey,
    CryptoAddress,
    MacAddress,
    Hostname,
    UserPath,
    PersonName,
    PhysicalAddress,
    PassportNumber,
    DriversLicense,
    Ssn,
    Bsn,
    Nino,
    NhsNumber,
    Aadhaar,
    Pan,
    Cpf,
    Cnpj,
    SteuerId,
    InseeNir,
}

impl From<EntityTypeArg> for EntityType {
    fn from(value: EntityTypeArg) -> Self {
        match value {
            EntityTypeArg::Email => Self::Email,
            EntityTypeArg::PhoneNumber => Self::PhoneNumber,
            EntityTypeArg::CreditCard => Self::CreditCard,
            EntityTypeArg::Iban => Self::Iban,
            EntityTypeArg::IpAddress => Self::IpAddress,
            EntityTypeArg::Url => Self::Url,
            EntityTypeArg::DateOfBirth => Self::DateOfBirth,
            EntityTypeArg::ApiKey => Self::ApiKey,
            EntityTypeArg::Jwt => Self::Jwt,
            EntityTypeArg::AwsAccessKey => Self::AwsAccessKey,
            EntityTypeArg::CryptoAddress => Self::CryptoAddress,
            EntityTypeArg::MacAddress => Self::MacAddress,
            EntityTypeArg::Hostname => Self::Hostname,
            EntityTypeArg::UserPath => Self::UserPath,
            EntityTypeArg::PersonName => Self::PersonName,
            EntityTypeArg::PhysicalAddress => Self::PhysicalAddress,
            EntityTypeArg::PassportNumber => Self::PassportNumber,
            EntityTypeArg::DriversLicense => Self::DriversLicense,
            EntityTypeArg::Ssn => Self::Ssn,
            EntityTypeArg::Bsn => Self::Bsn,
            EntityTypeArg::Nino => Self::Nino,
            EntityTypeArg::NhsNumber => Self::NhsNumber,
            EntityTypeArg::Aadhaar => Self::Aadhaar,
            EntityTypeArg::Pan => Self::Pan,
            EntityTypeArg::Cpf => Self::Cpf,
            EntityTypeArg::Cnpj => Self::Cnpj,
            EntityTypeArg::SteuerId => Self::SteuerID,
            EntityTypeArg::InseeNir => Self::InseeNir,
        }
    }
}

/// Audit severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[value(rename_all = "kebab-case")]
#[serde(rename_all = "lowercase")]
pub enum SeverityArg {
    /// Low severity and above.
    Low,
    /// Medium severity and above.
    Medium,
    /// High severity only.
    High,
}

/// Dispatches the parsed command.
pub fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Scan(args) => run_scan(&cli.global, &args),
        Command::Stream(args) => run_stream(&cli.global, &args),
        Command::Audit(args) => run_audit(&cli.global, &args),
        Command::PreCommit(args) => run_pre_commit(&cli.global, &args),
    }
}

fn run_scan(global: &GlobalOptions, args: &ScanArgs) -> ExitCode {
    match scan_file(global, args) {
        Ok(found_pii) => {
            if found_pii {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("cloakrs scan: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_stream(global: &GlobalOptions, _args: &StreamArgs) -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    match stream_reader(global, stdin.lock(), stdout.lock()) {
        Ok(summary) => {
            if let Err(error) = write_audit_events(global, &summary.audit_events) {
                eprintln!("cloakrs stream: {error}");
                return ExitCode::from(2);
            }
            if !global.quiet {
                eprintln!("{}", render_stream_summary(&summary, global.output_format));
            }
            if summary.total_findings > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("cloakrs stream: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_audit(global: &GlobalOptions, args: &AuditArgs) -> ExitCode {
    match audit_directory(global, args) {
        Ok(report) => {
            let found_pii = report.total_findings > 0;
            if let Err(error) =
                write_audit_events(global, &audit_events_from_audit_report(&report, "audit"))
            {
                eprintln!("cloakrs audit: {error}");
                return ExitCode::from(2);
            }
            match render_audit_report(&report, global.output_format) {
                Ok(rendered) => {
                    if let Some(output) = &args.output {
                        if let Err(error) = fs::write(output, rendered.as_bytes()) {
                            eprintln!(
                                "cloakrs audit: failed to write {}: {error}",
                                output.display()
                            );
                            return ExitCode::from(2);
                        }
                    } else if let Err(error) = write_stdout(&rendered) {
                        eprintln!("cloakrs audit: {error}");
                        return ExitCode::from(2);
                    }
                    if found_pii {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("cloakrs audit: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("cloakrs audit: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_pre_commit(global: &GlobalOptions, args: &PreCommitArgs) -> ExitCode {
    match pre_commit_paths(global, args) {
        Ok(report) => {
            let found_pii = report.total_findings > 0;
            if let Err(error) = write_audit_events(
                global,
                &audit_events_from_audit_report(&report, "pre-commit"),
            ) {
                eprintln!("cloakrs pre-commit: {error}");
                return ExitCode::from(2);
            }
            match render_audit_report(&report, global.output_format) {
                Ok(rendered) => {
                    if let Some(output) = &args.output {
                        if let Err(error) = fs::write(output, rendered.as_bytes()) {
                            eprintln!(
                                "cloakrs pre-commit: failed to write {}: {error}",
                                output.display()
                            );
                            return ExitCode::from(2);
                        }
                    } else if !global.quiet || found_pii {
                        if let Err(error) = write_stdout(&rendered) {
                            eprintln!("cloakrs pre-commit: {error}");
                            return ExitCode::from(2);
                        }
                    }
                    if found_pii {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("cloakrs pre-commit: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("cloakrs pre-commit: {error}");
            ExitCode::from(2)
        }
    }
}

fn parse_confidence(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid confidence value: {error}"))?;
    if parsed.is_finite() && (0.0..=1.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("confidence must be between 0.0 and 1.0".to_string())
    }
}

fn scan_file(global: &GlobalOptions, args: &ScanArgs) -> Result<bool, String> {
    let progress = progress_bar(&args.path, global)?;
    let input = fs::read_to_string(&args.path)
        .map_err(|error| format!("failed to read {}: {error}", args.path.display()))?;
    if let Some(progress) = &progress {
        progress.set_position(input.len() as u64);
    }
    let format = detect_format(&args.path, args.format);
    let scanner = build_scanner(global)?;
    let report = scan_input(&input, format, &scanner, args)?;
    if let Some(progress) = progress {
        progress.finish_and_clear();
    }
    let found_pii = !report.findings.is_empty();
    write_audit_events(
        global,
        &audit_events_from_adapter_report(&args.path, &report, "scan"),
    )?;

    if let Some(output) = &args.output {
        fs::write(output, report.masked_output.as_bytes())
            .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    }

    if global.quiet {
        if args.output.is_none() {
            write_stdout(&report.masked_output)?;
        }
        return Ok(found_pii);
    }

    let rendered = render_scan_report(&args.path, format, &report, global.output_format)?;
    write_stdout(&rendered)?;
    Ok(found_pii)
}

fn stream_reader<R, W>(
    global: &GlobalOptions,
    reader: R,
    writer: W,
) -> Result<StreamSummary, String>
where
    R: BufRead,
    W: Write,
{
    let scanner = build_scanner(global)?;
    let lines = mask_log_reader(reader, writer, &scanner).map_err(|error| error.to_string())?;
    Ok(StreamSummary::from_lines(lines))
}

fn audit_directory(global: &GlobalOptions, args: &AuditArgs) -> Result<AuditReport, String> {
    if !args.path.is_dir() {
        return Err(format!("{} is not a directory", args.path.display()));
    }

    let scanner = build_scanner(global)?;
    let paths = collect_audit_paths(args)?;
    let progress = audit_progress(paths.len(), global);
    let outcomes = scan_audit_paths(&paths, &scanner, args, progress.as_ref())?;
    if let Some(progress) = progress {
        progress.finish_and_clear();
    }

    Ok(AuditReport::from_outcomes(
        args.path.display().to_string(),
        args.severity,
        outcomes,
    ))
}

fn pre_commit_paths(global: &GlobalOptions, args: &PreCommitArgs) -> Result<AuditReport, String> {
    let scanner = build_scanner(global)?;
    if args.paths.is_empty() {
        return Ok(AuditReport::from_outcomes(
            "pre-commit".to_string(),
            args.severity,
            Vec::new(),
        ));
    }

    let outcomes = args
        .paths
        .iter()
        .map(|path| scan_audit_path(path, &scanner, args.severity, None))
        .collect();
    Ok(AuditReport::from_outcomes(
        "pre-commit".to_string(),
        args.severity,
        outcomes,
    ))
}

fn collect_audit_paths(args: &AuditArgs) -> Result<Vec<PathBuf>, String> {
    let mut builder = WalkBuilder::new(&args.path);
    builder
        .git_ignore(args.respect_gitignore)
        .git_global(args.respect_gitignore)
        .git_exclude(args.respect_gitignore);
    if !args.recursive {
        builder.max_depth(Some(1));
    }

    let mut paths = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn scan_audit_paths(
    paths: &[PathBuf],
    scanner: &Scanner,
    args: &AuditArgs,
    progress: Option<&ProgressBar>,
) -> Result<Vec<AuditScanOutcome>, String> {
    if let Some(threads) = args.parallel {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|error| error.to_string())?;
        return Ok(pool.install(|| {
            paths
                .par_iter()
                .map(|path| scan_audit_path(path, scanner, args.severity, progress))
                .collect()
        }));
    }

    Ok(paths
        .par_iter()
        .map(|path| scan_audit_path(path, scanner, args.severity, progress))
        .collect())
}

fn scan_audit_path(
    path: &Path,
    scanner: &Scanner,
    min_severity: SeverityArg,
    progress: Option<&ProgressBar>,
) -> AuditScanOutcome {
    let outcome = match read_text_file(path) {
        Ok(input) => {
            let format = detect_format(path, InputFormat::Auto);
            match scan_input(&input, format, scanner, &audit_scan_args(path, format)) {
                Ok(report) => AuditScanOutcome::Scanned(AuditFileReport::from_adapter_report(
                    path,
                    format,
                    report,
                    min_severity,
                )),
                Err(_) => AuditScanOutcome::Skipped,
            }
        }
        Err(_) => AuditScanOutcome::Skipped,
    };
    if let Some(progress) = progress {
        progress.inc(1);
    }
    outcome
}

fn audit_scan_args(path: &Path, format: InputFormat) -> ScanArgs {
    ScanArgs {
        path: path.to_path_buf(),
        format,
        output: None,
        columns: Vec::new(),
        include_paths: Vec::new(),
        exclude_paths: Vec::new(),
    }
}

fn read_text_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.contains(&0) {
        return Err("binary file".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "non-utf8 file".to_string())
}

fn build_scanner(global: &GlobalOptions) -> Result<Scanner, String> {
    let config = load_config(global.config.as_deref())?;
    let config_exclusions = config.exclude_entities();
    let mut builder = cloakrs_locales::default_registry()
        .into_scanner_builder()
        .locale(selected_locale(&global.locale))
        .exclude_entities(
            global
                .exclude_entities
                .iter()
                .chain(config_exclusions.iter())
                .copied()
                .map(EntityType::from),
        )
        .strategy(mask_strategy(global.strategy)?)
        .allow_list(config.allow_list())
        .deny_list(config.deny_list());
    builder = builder
        .min_confidence(global.min_confidence)
        .map_err(|error| error.to_string())?;
    builder.build().map_err(|error| error.to_string())
}

#[derive(Debug, Default, Deserialize)]
struct CloakConfig {
    #[serde(default)]
    allow_list: Vec<String>,
    #[serde(default)]
    deny_list: Vec<String>,
    #[serde(default)]
    exclude_entities: Vec<EntityTypeArg>,
    #[serde(default)]
    scanner: ScannerConfig,
}

#[derive(Debug, Default, Deserialize)]
struct ScannerConfig {
    #[serde(default)]
    allow_list: Vec<String>,
    #[serde(default)]
    deny_list: Vec<String>,
    #[serde(default)]
    exclude_entities: Vec<EntityTypeArg>,
}

impl CloakConfig {
    fn allow_list(&self) -> Vec<String> {
        self.allow_list
            .iter()
            .chain(self.scanner.allow_list.iter())
            .cloned()
            .collect()
    }

    fn deny_list(&self) -> Vec<String> {
        self.deny_list
            .iter()
            .chain(self.scanner.deny_list.iter())
            .cloned()
            .collect()
    }

    fn exclude_entities(&self) -> Vec<EntityTypeArg> {
        self.exclude_entities
            .iter()
            .chain(self.scanner.exclude_entities.iter())
            .copied()
            .collect()
    }
}

fn load_config(explicit: Option<&Path>) -> Result<CloakConfig, String> {
    let Some(path) = explicit.map(PathBuf::from).or_else(find_default_config) else {
        return Ok(CloakConfig::default());
    };
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read config {}: {error}", path.display()))?;
    toml::from_str(&contents)
        .map_err(|error| format!("failed to parse config {}: {error}", path.display()))
}

fn find_default_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".cloakrs.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn scan_input(
    input: &str,
    format: InputFormat,
    scanner: &Scanner,
    args: &ScanArgs,
) -> Result<AdapterReport, String> {
    match format {
        InputFormat::Auto => scan_input(input, InputFormat::Text, scanner, args),
        InputFormat::Text => {
            let lines = scan_text(input, scanner).map_err(|error| error.to_string())?;
            let findings = lines
                .iter()
                .filter(|line| !line.findings.is_empty())
                .map(|line| AdapterFinding {
                    location: format!("line:{}", line.line_number),
                    findings: line.findings.clone(),
                    masked_value: line.masked_line.clone(),
                })
                .collect();
            let masked_output = masked_plaintext_output(input, &lines);
            Ok(AdapterReport {
                kind: AdapterKind::Plaintext,
                findings,
                masked_output,
            })
        }
        InputFormat::Json => {
            let options = JsonScanOptions {
                include_paths: args.include_paths.clone(),
                exclude_paths: args.exclude_paths.clone(),
            };
            let result =
                scan_json_str(input, scanner, &options).map_err(|error| error.to_string())?;
            Ok(AdapterReport {
                kind: AdapterKind::Json,
                findings: result
                    .strings
                    .into_iter()
                    .map(|string| AdapterFinding {
                        location: string.path,
                        findings: string.findings,
                        masked_value: string.masked_value,
                    })
                    .collect(),
                masked_output: serde_json::to_string_pretty(&result.masked_json)
                    .map_err(|error| error.to_string())?,
            })
        }
        InputFormat::Csv => {
            let (columns, column_indexes) = split_csv_columns(&args.columns);
            let options = CsvScanOptions {
                has_headers: true,
                columns,
                column_indexes,
                delimiter: b',',
            };
            let result =
                scan_csv_str(input, scanner, &options).map_err(|error| error.to_string())?;
            Ok(AdapterReport {
                kind: AdapterKind::Csv,
                findings: result
                    .cells
                    .into_iter()
                    .map(|cell| AdapterFinding {
                        location: format!("row:{},column:{}", cell.row_number, cell.column_index),
                        findings: cell.findings,
                        masked_value: cell.masked_value,
                    })
                    .collect(),
                masked_output: result.masked_csv,
            })
        }
        InputFormat::Log => {
            let result = scan_log_str(input, scanner).map_err(|error| error.to_string())?;
            Ok(AdapterReport {
                kind: AdapterKind::LogStream,
                findings: result
                    .lines
                    .into_iter()
                    .filter(|line| !line.findings.is_empty())
                    .map(|line| AdapterFinding {
                        location: format!("line:{}", line.line_number),
                        findings: line.findings,
                        masked_value: line.masked_line,
                    })
                    .collect(),
                masked_output: result.masked_log,
            })
        }
        InputFormat::Sql => {
            let result = scan_sql_str(input, scanner).map_err(|error| error.to_string())?;
            Ok(AdapterReport {
                kind: AdapterKind::Sql,
                findings: result
                    .values
                    .into_iter()
                    .map(|value| AdapterFinding {
                        location: format!(
                            "statement:{},value:{}",
                            value.statement_number, value.value_index
                        ),
                        findings: value.findings,
                        masked_value: value.masked_value,
                    })
                    .collect(),
                masked_output: result.masked_sql,
            })
        }
    }
}

fn render_scan_report(
    path: &Path,
    format: InputFormat,
    report: &AdapterReport,
    output_format: OutputFormat,
) -> Result<String, String> {
    match output_format {
        OutputFormat::Text => Ok(render_text_report(path, format, report)),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&ScanReportJson::from_report(path, format, report))
                .map_err(|error| error.to_string())
        }
        OutputFormat::Sarif => render_sarif(&sarif_findings_from_report(path, report)),
    }
}

fn render_text_report(path: &Path, format: InputFormat, report: &AdapterReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("file: {}\n", path.display()));
    output.push_str(&format!("format: {format:?}\n"));
    output.push_str(&format!("findings: {}\n", total_findings(report)));
    for location in &report.findings {
        output.push_str(&format!("\n{}\n", location.location));
        for finding in &location.findings {
            output.push_str(&format!(
                "  {:?} {} confidence={} recognizer={}\n",
                finding.entity_type, finding.text, finding.confidence, finding.recognizer_id
            ));
        }
    }
    output
}

fn render_stream_summary(summary: &StreamSummary, output_format: OutputFormat) -> String {
    match output_format {
        OutputFormat::Json => serde_json::to_string_pretty(summary).unwrap_or_else(|error| {
            format!(
                "stream summary serialization failed: {error}; findings={}",
                summary.total_findings
            )
        }),
        OutputFormat::Text | OutputFormat::Sarif => {
            let mut output = String::new();
            output.push_str("stream summary\n");
            output.push_str(&format!("lines scanned: {}\n", summary.lines_scanned));
            output.push_str(&format!(
                "lines with findings: {}\n",
                summary.lines_with_findings
            ));
            output.push_str(&format!("findings: {}\n", summary.total_findings));
            for (entity_type, count) in &summary.findings_by_type {
                output.push_str(&format!("{entity_type}: {count}\n"));
            }
            output.trim_end().to_string()
        }
    }
}

#[derive(Debug, Serialize)]
struct ScanReportJson<'a> {
    file: String,
    format: InputFormat,
    adapter: AdapterKind,
    total_findings: usize,
    findings_by_type: BTreeMap<String, usize>,
    findings: &'a [AdapterFinding],
}

impl<'a> ScanReportJson<'a> {
    fn from_report(path: &Path, format: InputFormat, report: &'a AdapterReport) -> Self {
        Self {
            file: path.display().to_string(),
            format,
            adapter: report.kind,
            total_findings: total_findings(report),
            findings_by_type: findings_by_type(report),
            findings: &report.findings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct StreamSummary {
    lines_scanned: usize,
    lines_with_findings: usize,
    total_findings: usize,
    findings_by_type: BTreeMap<String, usize>,
    #[serde(skip)]
    audit_events: Vec<AuditLogEvent>,
}

impl StreamSummary {
    fn from_lines(lines: Vec<LogLineScanResult>) -> Self {
        let lines_scanned = lines.len();
        let lines_with_findings = lines
            .iter()
            .filter(|line| !line.findings.is_empty())
            .count();
        let mut findings_by_type = BTreeMap::new();
        let mut total_findings = 0;
        let mut audit_events = Vec::new();
        for line in lines {
            total_findings += line.findings.len();
            for finding in line.findings {
                *findings_by_type
                    .entry(format!("{:?}", finding.entity_type))
                    .or_insert(0) += 1;
                audit_events.push(audit_event(
                    "stream",
                    None,
                    format!("line:{}", line.line_number),
                    &finding,
                ));
            }
        }

        Self {
            lines_scanned,
            lines_with_findings,
            total_findings,
            findings_by_type,
            audit_events,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct AuditLogEvent {
    timestamp_unix_ms: u128,
    command: String,
    source: Option<String>,
    location: String,
    entity_type: String,
    action: String,
    confidence: f64,
    recognizer_id: String,
    span_start: usize,
    span_end: usize,
    text_length: usize,
}

fn audit_events_from_adapter_report(
    path: &Path,
    report: &AdapterReport,
    command: &str,
) -> Vec<AuditLogEvent> {
    report
        .findings
        .iter()
        .flat_map(|location| {
            location.findings.iter().map(|finding| {
                audit_event(
                    command,
                    Some(path.display().to_string()),
                    location.location.clone(),
                    finding,
                )
            })
        })
        .collect()
}

fn audit_events_from_audit_report(report: &AuditReport, command: &str) -> Vec<AuditLogEvent> {
    report
        .files
        .iter()
        .flat_map(|file| {
            file.findings.iter().flat_map(move |location| {
                location.findings.iter().map(move |finding| {
                    audit_event(
                        command,
                        Some(file.path.clone()),
                        location.location.clone(),
                        finding,
                    )
                })
            })
        })
        .collect()
}

fn audit_event(
    command: &str,
    source: Option<String>,
    location: String,
    finding: &cloakrs_core::PiiEntity,
) -> AuditLogEvent {
    AuditLogEvent {
        timestamp_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis()),
        command: command.to_string(),
        source,
        location,
        entity_type: format!("{:?}", finding.entity_type),
        action: "masked".to_string(),
        confidence: finding.confidence.value(),
        recognizer_id: finding.recognizer_id.clone(),
        span_start: finding.span.start,
        span_end: finding.span.end,
        text_length: finding.text.len(),
    }
}

fn write_audit_events(global: &GlobalOptions, events: &[AuditLogEvent]) -> Result<(), String> {
    let Some(path) = &global.audit_log else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("failed to open audit log {}: {error}", path.display()))?;
    for event in events {
        serde_json::to_writer(&mut file, event).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum AuditScanOutcome {
    Scanned(AuditFileReport),
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
struct AuditReport {
    root: String,
    minimum_severity: SeverityArg,
    files_scanned: usize,
    files_skipped: usize,
    total_findings: usize,
    findings_by_type: BTreeMap<String, usize>,
    severity: SeverityArg,
    files: Vec<AuditFileReport>,
}

impl AuditReport {
    fn from_outcomes(
        root: String,
        minimum_severity: SeverityArg,
        outcomes: Vec<AuditScanOutcome>,
    ) -> Self {
        let mut files_scanned = 0;
        let mut files_skipped = 0;
        let mut total_findings = 0;
        let mut findings_by_type = BTreeMap::new();
        let mut severity = SeverityArg::Low;
        let mut files = Vec::new();

        for outcome in outcomes {
            match outcome {
                AuditScanOutcome::Scanned(file) => {
                    files_scanned += 1;
                    if file.total_findings > 0 {
                        total_findings += file.total_findings;
                        severity = max_severity(severity, file.severity);
                        for (entity_type, count) in &file.findings_by_type {
                            *findings_by_type.entry(entity_type.clone()).or_insert(0) += count;
                        }
                        files.push(file);
                    }
                }
                AuditScanOutcome::Skipped => files_skipped += 1,
            }
        }

        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            root,
            minimum_severity,
            files_scanned,
            files_skipped,
            total_findings,
            findings_by_type,
            severity,
            files,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct AuditFileReport {
    path: String,
    format: InputFormat,
    adapter: AdapterKind,
    total_findings: usize,
    findings_by_type: BTreeMap<String, usize>,
    severity: SeverityArg,
    findings: Vec<AdapterFinding>,
}

impl AuditFileReport {
    fn from_adapter_report(
        path: &Path,
        format: InputFormat,
        report: AdapterReport,
        min_severity: SeverityArg,
    ) -> Self {
        let findings = filter_findings_by_severity(report.findings, min_severity);
        let total_findings = findings
            .iter()
            .map(|location| location.findings.len())
            .sum();
        let findings_by_type = findings_by_type_for_locations(&findings);
        let severity = max_location_severity(&findings);

        Self {
            path: path.display().to_string(),
            format,
            adapter: report.kind,
            total_findings,
            findings_by_type,
            severity,
            findings,
        }
    }
}

fn filter_findings_by_severity(
    findings: Vec<AdapterFinding>,
    min_severity: SeverityArg,
) -> Vec<AdapterFinding> {
    findings
        .into_iter()
        .filter_map(|mut location| {
            location.findings.retain(|finding| {
                severity_rank(finding_severity(&finding.entity_type)) >= severity_rank(min_severity)
            });
            if location.findings.is_empty() {
                None
            } else {
                Some(location)
            }
        })
        .collect()
}

fn findings_by_type_for_locations(findings: &[AdapterFinding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for location in findings {
        for finding in &location.findings {
            *counts
                .entry(format!("{:?}", finding.entity_type))
                .or_insert(0) += 1;
        }
    }
    counts
}

fn max_location_severity(findings: &[AdapterFinding]) -> SeverityArg {
    findings
        .iter()
        .flat_map(|location| &location.findings)
        .map(|finding| finding_severity(&finding.entity_type))
        .fold(SeverityArg::Low, max_severity)
}

fn max_severity(left: SeverityArg, right: SeverityArg) -> SeverityArg {
    if severity_rank(right) > severity_rank(left) {
        right
    } else {
        left
    }
}

fn severity_rank(severity: SeverityArg) -> u8 {
    match severity {
        SeverityArg::Low => 0,
        SeverityArg::Medium => 1,
        SeverityArg::High => 2,
    }
}

fn finding_severity(entity_type: &EntityType) -> SeverityArg {
    match entity_type {
        EntityType::CreditCard | EntityType::Ssn => SeverityArg::High,
        EntityType::Email | EntityType::PhoneNumber | EntityType::Iban => SeverityArg::Medium,
        _ => SeverityArg::Low,
    }
}

fn render_audit_report(
    report: &AuditReport,
    output_format: OutputFormat,
) -> Result<String, String> {
    match output_format {
        OutputFormat::Text => Ok(render_audit_text_report(report)),
        OutputFormat::Json => {
            serde_json::to_string_pretty(report).map_err(|error| error.to_string())
        }
        OutputFormat::Sarif => render_sarif(&sarif_findings_from_audit(report)),
    }
}

fn render_audit_text_report(report: &AuditReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("audit root: {}\n", report.root));
    output.push_str(&format!("files scanned: {}\n", report.files_scanned));
    output.push_str(&format!("files skipped: {}\n", report.files_skipped));
    output.push_str(&format!("findings: {}\n", report.total_findings));
    output.push_str(&format!("severity: {:?}\n", report.severity));

    if !report.findings_by_type.is_empty() {
        output.push_str("\nfindings by type\n");
        for (entity_type, count) in &report.findings_by_type {
            output.push_str(&format!("  {entity_type}: {count}\n"));
        }
    }

    if !report.files.is_empty() {
        output.push_str("\nfiles\n");
        for file in &report.files {
            output.push_str(&format!(
                "  {}: {} findings ({:?})\n",
                file.path, file.total_findings, file.severity
            ));
            for (entity_type, count) in &file.findings_by_type {
                output.push_str(&format!("    {entity_type}: {count}\n"));
            }
        }
    }

    output
}

fn render_sarif(findings: &[SarifFinding]) -> Result<String, String> {
    let log = sarif::sarif_log(findings);
    sarif::validate_sarif_shape(&log)?;
    serde_json::to_string_pretty(&log).map_err(|error| error.to_string())
}

fn sarif_findings_from_report(path: &Path, report: &AdapterReport) -> Vec<SarifFinding> {
    let uri = path.display().to_string();
    report
        .findings
        .iter()
        .flat_map(|location| {
            location
                .findings
                .iter()
                .map(|finding| SarifFinding::from_pii(&uri, &location.location, finding))
        })
        .collect()
}

fn sarif_findings_from_audit(report: &AuditReport) -> Vec<SarifFinding> {
    report
        .files
        .iter()
        .flat_map(|file| {
            file.findings.iter().flat_map(|location| {
                location
                    .findings
                    .iter()
                    .map(|finding| SarifFinding::from_pii(&file.path, &location.location, finding))
            })
        })
        .collect()
}

fn audit_progress(total: usize, global: &GlobalOptions) -> Option<ProgressBar> {
    if global.quiet || total < 100 {
        return None;
    }

    let progress = ProgressBar::new(total as u64);
    if let Ok(style) = ProgressStyle::with_template("{spinner:.green} auditing {pos}/{len} files") {
        progress.set_style(style);
    }
    Some(progress)
}

fn detect_format(path: &Path, requested: InputFormat) -> InputFormat {
    if requested != InputFormat::Auto {
        return requested;
    }

    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => InputFormat::Json,
        Some("csv") => InputFormat::Csv,
        Some("log") => InputFormat::Log,
        Some("sql") => InputFormat::Sql,
        _ => InputFormat::Text,
    }
}

fn selected_locale(locales: &[LocaleArg]) -> Locale {
    locales
        .iter()
        .copied()
        .find(|locale| *locale != LocaleArg::Universal)
        .unwrap_or(LocaleArg::Universal)
        .into()
}

fn mask_strategy(strategy: StrategyArg) -> Result<MaskStrategy, String> {
    match strategy {
        StrategyArg::Redact => Ok(MaskStrategy::Redact),
        StrategyArg::PartialMask => Ok(MaskStrategy::PartialMask {
            reveal_prefix: 1,
            reveal_suffix: 4,
            mask_char: '*',
        }),
        StrategyArg::Hash => Ok(MaskStrategy::Hash { salt: None }),
        StrategyArg::Replace => Ok(MaskStrategy::Replace),
        StrategyArg::Encrypt => Err(
            "encrypt strategy requires key management and is not wired into the CLI yet"
                .to_string(),
        ),
    }
}

fn split_csv_columns(columns: &[String]) -> (Vec<String>, Vec<usize>) {
    let mut names = Vec::new();
    let mut indexes = Vec::new();
    for column in columns {
        match column.parse::<usize>() {
            Ok(index) => indexes.push(index),
            Err(_) => names.push(column.clone()),
        }
    }
    (names, indexes)
}

fn total_findings(report: &AdapterReport) -> usize {
    report
        .findings
        .iter()
        .map(|location| location.findings.len())
        .sum()
}

fn findings_by_type(report: &AdapterReport) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for location in &report.findings {
        for finding in &location.findings {
            *counts
                .entry(format!("{:?}", finding.entity_type))
                .or_insert(0) += 1;
        }
    }
    counts
}

fn masked_plaintext_output(input: &str, lines: &[cloakrs_adapters::LineScanResult]) -> String {
    let mut output = String::with_capacity(input.len());
    for (index, segment) in input.split_inclusive('\n').enumerate() {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let masked = lines
            .get(index)
            .and_then(|result| result.masked_line.as_deref())
            .unwrap_or(line);
        output.push_str(masked);
        if segment.ends_with('\n') {
            if segment.ends_with("\r\n") {
                output.push('\r');
            }
            output.push('\n');
        }
    }
    if !input.contains('\n') {
        return lines
            .first()
            .and_then(|result| result.masked_line.clone())
            .unwrap_or_else(|| input.to_string());
    }
    output
}

fn write_stdout(output: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .and_then(|_| {
            if output.ends_with('\n') {
                Ok(())
            } else {
                stdout.write_all(b"\n")
            }
        })
        .map_err(|error| format!("failed to write stdout: {error}"))
}

fn progress_bar(path: &Path, global: &GlobalOptions) -> Result<Option<ProgressBar>, String> {
    if global.quiet {
        return Ok(None);
    }

    let size = fs::metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
        .len();
    if size < 1_000_000 {
        return Ok(None);
    }

    let progress = ProgressBar::new(size);
    if let Ok(style) =
        ProgressStyle::with_template("{spinner:.green} scanning {bytes}/{total_bytes} {msg}")
    {
        progress.set_style(style);
    }
    progress.set_message(path.display().to_string());
    Ok(Some(progress))
}

impl From<LocaleArg> for Locale {
    fn from(value: LocaleArg) -> Self {
        match value {
            LocaleArg::Universal => Self::Universal,
            LocaleArg::Us => Self::US,
            LocaleArg::Nl => Self::NL,
            LocaleArg::Uk => Self::UK,
            LocaleArg::De => Self::DE,
            LocaleArg::Fr => Self::FR,
            LocaleArg::In => Self::IN,
            LocaleArg::Br => Self::BR,
            LocaleArg::Eu => Self::EU,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_help_builds() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_scan_parses_global_and_scan_options() {
        let cli = Cli::parse_from([
            "cloakrs",
            "--locale",
            "eu,nl",
            "--exclude-entities",
            "url,hostname,user-path",
            "--strategy",
            "partial-mask",
            "--min-confidence",
            "0.8",
            "--output-format",
            "json",
            "scan",
            "data.csv",
            "--format",
            "csv",
            "--columns",
            "email,phone",
        ]);

        assert_eq!(cli.global.locale, vec![LocaleArg::Eu, LocaleArg::Nl]);
        assert_eq!(
            cli.global.exclude_entities,
            [
                EntityTypeArg::Url,
                EntityTypeArg::Hostname,
                EntityTypeArg::UserPath
            ]
        );
        assert_eq!(cli.global.strategy, StrategyArg::PartialMask);
        assert_eq!(cli.global.min_confidence, 0.8);
        assert_eq!(cli.global.output_format, OutputFormat::Json);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(args.format, InputFormat::Csv);
        assert_eq!(args.columns, ["email", "phone"]);
    }

    #[test]
    fn test_cli_stream_accepts_quiet_global_after_subcommand() {
        let cli = Cli::parse_from(["cloakrs", "stream", "--quiet"]);
        assert!(cli.global.quiet);
        assert!(matches!(cli.command, Command::Stream(_)));
    }

    #[test]
    fn test_cli_pre_commit_accepts_paths() {
        let cli = Cli::parse_from([
            "cloakrs",
            "--config",
            ".cloakrs.toml",
            "pre-commit",
            "src/lib.rs",
            "README.md",
        ]);
        assert_eq!(cli.global.config, Some(PathBuf::from(".cloakrs.toml")));
        let Command::PreCommit(args) = cli.command else {
            panic!("expected pre-commit command");
        };
        assert_eq!(
            args.paths,
            [PathBuf::from("src/lib.rs"), PathBuf::from("README.md")]
        );
    }

    #[test]
    fn test_cli_rejects_unknown_excluded_entity() {
        let error = Cli::try_parse_from([
            "cloakrs",
            "--exclude-entities",
            "url,not-an-entity",
            "stream",
        ])
        .expect_err("unknown entities should fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn test_cli_rejects_invalid_min_confidence() {
        let error = Cli::try_parse_from(["cloakrs", "--min-confidence", "2", "stream"])
            .expect_err("confidence above one should fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn test_detect_format_uses_extension_for_auto() {
        assert_eq!(
            detect_format(Path::new("sample.json"), InputFormat::Auto),
            InputFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("sample.txt"), InputFormat::Auto),
            InputFormat::Text
        );
    }

    #[test]
    fn test_split_csv_columns_separates_names_and_indexes() {
        let (names, indexes) = split_csv_columns(&["email".to_string(), "2".to_string()]);
        assert_eq!(names, ["email"]);
        assert_eq!(indexes, [2]);
    }

    #[test]
    fn test_sarif_rule_id_uses_upper_snake_case() {
        assert_eq!(
            sarif::rule_id(&EntityType::CreditCard),
            "CREDIT_CARD_DETECTED"
        );
        assert_eq!(sarif::rule_id(&EntityType::PhoneNumber), "PHONE_DETECTED");
    }

    #[test]
    fn test_stream_reader_masks_lines_and_counts_findings() {
        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: None,
        };
        let input = "email jane@example.com\nplain\n";
        let mut output = Vec::new();
        let summary = stream_reader(&global, io::Cursor::new(input), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("[EMAIL]"));
        assert_eq!(summary.lines_scanned, 2);
        assert_eq!(summary.lines_with_findings, 1);
        assert_eq!(summary.total_findings, 1);
        assert_eq!(summary.audit_events.len(), 1);
    }

    #[test]
    fn test_stream_excludes_urls_but_redacts_other_entities() {
        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: vec![EntityTypeArg::Url],
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: None,
        };
        let input = "visit https://example.com and email jane@example.com\n";
        let mut output = Vec::new();
        let summary = stream_reader(&global, io::Cursor::new(input), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(output, "visit https://example.com and email [EMAIL]\n");
        assert_eq!(summary.total_findings, 1);
        assert_eq!(summary.findings_by_type.get("Email"), Some(&1));
    }

    #[test]
    fn test_render_stream_summary_json_uses_machine_readable_shape() {
        let summary = StreamSummary {
            lines_scanned: 2,
            lines_with_findings: 1,
            total_findings: 1,
            findings_by_type: BTreeMap::from([("Email".to_string(), 1)]),
            audit_events: Vec::new(),
        };
        let rendered = render_stream_summary(&summary, OutputFormat::Json);
        assert!(rendered.contains("\"total_findings\": 1"));
    }

    #[test]
    fn test_audit_directory_scans_text_and_skips_binary() {
        let root = unique_temp_dir("audit_scans_text");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sample.txt"), "contact jane@example.com\n").unwrap();
        fs::write(root.join("binary.bin"), b"\0\0\0").unwrap();

        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: None,
        };
        let args = AuditArgs {
            path: root.clone(),
            recursive: true,
            respect_gitignore: true,
            parallel: Some(2),
            severity: SeverityArg::Low,
            output: None,
        };

        let report = audit_directory(&global, &args).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.total_findings, 1);
        assert_eq!(report.findings_by_type.get("Email"), Some(&1));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_audit_directory_severity_filter_excludes_medium_findings() {
        let root = unique_temp_dir("audit_severity_filter");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sample.txt"), "contact jane@example.com\n").unwrap();

        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: None,
        };
        let args = AuditArgs {
            path: root.clone(),
            recursive: true,
            respect_gitignore: true,
            parallel: None,
            severity: SeverityArg::High,
            output: None,
        };

        let report = audit_directory(&global, &args).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.total_findings, 0);
        assert!(report.files.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_pre_commit_paths_scans_given_files() {
        let root = unique_temp_dir("pre_commit_scans_files");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("sample.txt");
        fs::write(&path, "contact jane@example.com\n").unwrap();

        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: None,
        };
        let args = PreCommitArgs {
            paths: vec![path],
            severity: SeverityArg::Low,
            output: None,
        };

        let report = pre_commit_paths(&global, &args).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.total_findings, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_config_allow_and_deny_lists_are_loaded() {
        let root = unique_temp_dir("config_lists");
        fs::create_dir_all(&root).unwrap();
        let config = root.join(".cloakrs.toml");
        fs::write(
            &config,
            r#"
allow_list = ["jane@example.com"]

[scanner]
deny_list = ["PRJ-12345"]
"#,
        )
        .unwrap();

        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: Some(config),
            audit_log: None,
        };
        let scanner = build_scanner(&global).unwrap();
        let result = scanner.scan("jane@example.com PRJ-12345").unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.masked_text.as_deref(),
            Some("jane@example.com [DENYLIST]")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_config_excludes_entities_and_preserves_nested_url_pii() {
        let root = unique_temp_dir("config_excluded_entities");
        fs::create_dir_all(&root).unwrap();
        let config = root.join(".cloakrs.toml");
        fs::write(
            &config,
            r#"
exclude_entities = ["url", "hostname"]

[scanner]
exclude_entities = ["user-path"]
"#,
        )
        .unwrap();

        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: Some(config),
            audit_log: None,
        };
        let scanner = build_scanner(&global).unwrap();
        let result = scanner
            .scan("visit https://example.com?email=jane%40example.com from /home/alice/project")
            .unwrap();
        let masked = result.masked_text.unwrap();

        assert!(result.findings.iter().all(|finding| !matches!(
            finding.entity_type,
            EntityType::Url | EntityType::Hostname | EntityType::UserPath
        )));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Email));
        assert!(masked.contains("https://example.com?email=[EMAIL]"));
        assert!(masked.contains("/home/alice/project"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_config_rejects_unknown_excluded_entity() {
        let root = unique_temp_dir("config_unknown_excluded_entity");
        fs::create_dir_all(&root).unwrap();
        let config = root.join(".cloakrs.toml");
        fs::write(&config, "exclude_entities = [\"not-an-entity\"]\n").unwrap();

        assert!(load_config(Some(&config)).is_err());
        let global = GlobalOptions {
            locale: vec![LocaleArg::Universal],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: Some(config),
            audit_log: None,
        };
        let audit_args = AuditArgs {
            path: root.clone(),
            recursive: true,
            respect_gitignore: true,
            parallel: None,
            severity: SeverityArg::Low,
            output: None,
        };
        let pre_commit_args = PreCommitArgs {
            paths: Vec::new(),
            severity: SeverityArg::Low,
            output: None,
        };
        assert!(audit_directory(&global, &audit_args).is_err());
        assert!(pre_commit_paths(&global, &pre_commit_args).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_write_audit_events_outputs_jsonl_without_raw_pii() {
        let root = unique_temp_dir("audit_jsonl");
        fs::create_dir_all(&root).unwrap();
        let audit_log = root.join("audit.jsonl");
        let global = GlobalOptions {
            locale: vec![LocaleArg::Us],
            exclude_entities: Vec::new(),
            strategy: StrategyArg::Redact,
            min_confidence: 0.5,
            output_format: OutputFormat::Text,
            quiet: true,
            config: None,
            audit_log: Some(audit_log.clone()),
        };
        let mut output = Vec::new();
        let summary = stream_reader(
            &global,
            io::Cursor::new("contact jane@example.com\n"),
            &mut output,
        )
        .unwrap();

        write_audit_events(&global, &summary.audit_events).unwrap();
        let contents = fs::read_to_string(&audit_log).unwrap();
        assert!(contents.contains("\"entity_type\":\"Email\""));
        assert!(contents.contains("\"command\":\"stream\""));
        assert!(!contents.contains("jane@example.com"));

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cloakrs_{name}_{}", std::process::id()))
    }
}
