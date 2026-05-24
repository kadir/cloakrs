use cloakrs_core::Recognizer;
use cloakrs_patterns::{
    ApiKeyRecognizer, AwsAccessKeyRecognizer, CreditCardRecognizer, CryptoAddressRecognizer,
    DateOfBirthRecognizer, EmailRecognizer, HostnameRecognizer, IbanRecognizer,
    IpAddressRecognizer, JwtRecognizer, MacAddressRecognizer, PersonNameRecognizer,
    PhoneRecognizer, PhysicalAddressRecognizer, SsnRecognizer, UrlRecognizer, UserPathRecognizer,
};

const CORPUS_LINES: usize = 10_000;

#[test]
fn test_false_positive_corpus_has_no_default_pattern_findings() {
    let corpus = no_pii_corpus(CORPUS_LINES);
    let recognizers: Vec<(&str, Box<dyn Recognizer>)> = vec![
        ("email", Box::new(EmailRecognizer)),
        ("phone", Box::new(PhoneRecognizer)),
        ("credit_card", Box::new(CreditCardRecognizer)),
        ("iban", Box::new(IbanRecognizer)),
        ("ssn", Box::new(SsnRecognizer)),
        ("ip_address", Box::new(IpAddressRecognizer)),
        ("url", Box::new(UrlRecognizer)),
        ("hostname", Box::new(HostnameRecognizer)),
        ("user_path", Box::new(UserPathRecognizer)),
        ("person_name", Box::new(PersonNameRecognizer)),
        ("physical_address", Box::new(PhysicalAddressRecognizer)),
        ("aws_access_key", Box::new(AwsAccessKeyRecognizer)),
        ("jwt", Box::new(JwtRecognizer)),
        ("api_key", Box::new(ApiKeyRecognizer)),
        ("mac_address", Box::new(MacAddressRecognizer)),
        ("crypto_address", Box::new(CryptoAddressRecognizer)),
        ("date_of_birth", Box::new(DateOfBirthRecognizer)),
    ];

    let mut failures = Vec::new();
    for (name, recognizer) in recognizers {
        let findings = recognizer.scan(&corpus);
        if !findings.is_empty() {
            failures.push(format!(
                "{name}: {} false positives, first={:?}",
                findings.len(),
                findings.first()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "false-positive corpus produced findings:\n{}",
        failures.join("\n")
    );
}

fn no_pii_corpus(lines: usize) -> String {
    let modules = [
        "cache", "queue", "worker", "parser", "render", "search", "billing", "metrics",
    ];
    let actions = [
        "started", "finished", "skipped", "retried", "queued", "merged", "indexed", "stored",
    ];
    let statuses = [
        "ok", "warm", "cold", "idle", "busy", "ready", "clean", "dry",
    ];

    let mut corpus = String::with_capacity(lines * 96);
    for index in 0..lines {
        let module = modules[index % modules.len()];
        let action = actions[(index / 3) % actions.len()];
        let status = statuses[(index / 7) % statuses.len()];
        corpus.push_str(&format!(
            "event id {index:05} module {module} action {action} status {status} count {} duration {}ms batch ref{:06}\n",
            20 + (index % 700),
            5 + (index % 400),
            100_000 + index
        ));
    }
    corpus
}
