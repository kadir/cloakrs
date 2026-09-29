//! Exclusion policy exercised through the public CLI and real format adapters.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn cli(root: &Path, args: &[&str], input: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cloakrs"))
        .current_dir(root)
        .args(["--config", "config.toml", "--quiet"])
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn expect(output: Output, status: i32) -> String {
    assert_eq!(
        output.status.code(),
        Some(status),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn cli_and_both_toml_sections_combine_without_losing_nested_pii() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("config.toml"),
        "exclude_entities = ['url']\n[scanner]\nexclude_entities = ['hostname']\n",
    )
    .unwrap();
    let input = "Résumé: https://example.com?email=jane%40example.com&ssn=123-45-6789 db-prod-01.internal.company.com /home/alice/project\n";
    let output = expect(
        cli(
            root,
            &[
                "--locale",
                "us",
                "--exclude-entities",
                "url,user-path,url",
                "stream",
            ],
            Some(input),
        ),
        1,
    );
    assert_eq!(output, "Résumé: https://example.com?email=[EMAIL]&ssn=[SSN] db-prod-01.internal.company.com /home/alice/project\n");

    // Excluding Email must also apply to the nested query finding, but not to SSN.
    let output = expect(
        cli(
            root,
            &[
                "--locale",
                "us",
                "--exclude-entities",
                "email,user-path",
                "stream",
            ],
            Some(input),
        ),
        1,
    );
    assert!(output.contains("?email=jane%40example.com&ssn=[SSN]"));
}

#[test]
fn sanitize_preserves_excluded_structure_and_restores_encoded_values_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("config.toml"),
        "exclude_entities = ['url', 'hostname', 'user-path']\n",
    )
    .unwrap();
    let input = "Résumé: https://example.com?email=jane%40example.com&ssn=123-45-6789\nhttps://example.com?email=jane%40example.com /home/alice/project\n";
    for style in ["brackets", "braces"] {
        let args = [
            "--locale",
            "us",
            "sanitize",
            "--mapping",
            "mapping.json",
            "--placeholder-style",
            style,
            "--force",
        ];
        let clean = expect(cli(root, &args, Some(input)), 0);
        let (email, ssn) = if style == "brackets" {
            ("[EMAIL_1]", "[SSN_1]")
        } else {
            ("{EMAIL_1}", "{SSN_1}")
        };
        assert_eq!(clean, format!("Résumé: https://example.com?email={email}&ssn={ssn}\nhttps://example.com?email={email} /home/alice/project\n"));
        let mapping: cloakrs_core::PromptMapping =
            serde_json::from_str(&fs::read_to_string(root.join("mapping.json")).unwrap()).unwrap();
        assert_eq!(mapping.entries().count(), 2);
        assert!(mapping
            .entries()
            .all(|entry| entry.entity_type != cloakrs_core::EntityType::Url));
        assert_eq!(mapping.restore(&clean), input);
        let restored = expect(
            cli(
                root,
                &["restore", "--mapping", "mapping.json", "--strict"],
                Some(&clean),
            ),
            0,
        );
        assert_eq!(restored, input);
    }
}

#[test]
fn json_scan_uses_exclusions_after_decoding_json_strings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("config.toml"), "exclude_entities = ['url']\n").unwrap();
    fs::write(
        root.join("input.json"),
        r#"{"url":"https://example.com?email=jane\u0040example.com","email":"jane@example.com"}"#,
    )
    .unwrap();
    let text = expect(
        cli(root, &["scan", "input.json", "--format", "json"], None),
        1,
    );
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["url"], "https://example.com?email=[EMAIL]");
    assert_eq!(value["email"], "[EMAIL]");
}

#[test]
fn audit_and_pre_commit_respect_exclusions_and_report_only_active_entities() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("config.toml"), "exclude_entities = ['url']\n").unwrap();
    fs::create_dir(root.join("inputs")).unwrap();
    fs::write(
        root.join("inputs/one.txt"),
        "https://example.com?email=jane%40example.com",
    )
    .unwrap();
    fs::write(
        root.join("inputs/two.txt"),
        "https://example.com /home/alice/project",
    )
    .unwrap();
    let extra = ["--exclude-entities", "user-path", "--output-format", "json"];
    for command in [
        vec!["audit", "inputs", "--parallel", "2"],
        vec!["pre-commit", "inputs/one.txt", "inputs/two.txt"],
    ] {
        let args: Vec<_> = extra.iter().copied().chain(command).collect();
        let output = expect(cli(root, &args, None), 1);
        let report: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["total_findings"], 1);
        assert_eq!(report["findings_by_type"], serde_json::json!({"Email": 1}));
    }
}

#[test]
fn invalid_configuration_is_an_error_for_every_scanning_command() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("config.toml"),
        "exclude_entities = ['not-an-entity']\n",
    )
    .unwrap();
    fs::write(root.join("input.txt"), "jane@example.com").unwrap();
    fs::create_dir(root.join("empty")).unwrap();
    for args in [
        vec!["scan", "input.txt"],
        vec!["stream"],
        vec!["audit", "empty"],
        vec!["pre-commit"],
        vec!["sanitize", "input.txt", "--mapping", "mapping.json"],
    ] {
        let output = cli(root, &args, None);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("not-an-entity"));
    }
    assert!(!root.join("mapping.json").exists());
}

#[test]
fn locale_selection_and_literal_lists_keep_their_meaning_with_exclusions() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("config.toml"), "exclude_entities = ['url', 'email']\nallow_list = ['kept@example.com']\ndeny_list = ['jane@example.com', 'kept@example.com']\n").unwrap();
    let input = "https://example.com BSN 123456782 jane@example.com kept@example.com\n";
    let output = expect(cli(root, &["--locale", "nl", "stream"], Some(input)), 1);
    assert_eq!(
        output,
        "https://example.com BSN [BSN] [DENYLIST] kept@example.com\n"
    );
    let output = expect(
        cli(
            root,
            &["--locale", "nl", "--exclude-entities", "bsn", "stream"],
            Some(input),
        ),
        1,
    );
    assert_eq!(
        output,
        "https://example.com BSN 123456782 [DENYLIST] kept@example.com\n"
    );
}
