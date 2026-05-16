use cloakrs_core::{decrypt_masked_value, EntityType, Locale, MaskStrategy};
use cloakrs_patterns::default_registry;
use std::time::Instant;

const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn test_scanner_with_default_patterns_detects_sprint_2_entities() {
    let registry = default_registry();
    let scanner = registry
        .into_scanner_builder()
        .locale(Locale::US)
        .build()
        .unwrap();

    let text = concat!(
        "email: jane@example.com\n",
        "phone: +1 (555) 123-4567\n",
        "card: 4111 1111 1111 1111\n",
        "iban: NL91ABNA0417164300\n",
        "ip: 203.0.113.42\n",
        "url: https://example.com/path\n",
        "aws: AKIAIOSFODNN7EXAMPLE\n",
        "jwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz\n",
        "api_key=sk_live_0123456789abcdef\n",
        "mac: 00:1A:2B:3C:4D:5E\n",
        "host: db-prod-01.internal.company.com\n",
        "path: /home/kadir/projects/app\n",
        "eth wallet 0xde709f2102306220921060314715629080e2fb77\n",
        "DOB: 1980-04-23\n",
        "ssn: 123-45-6789\n",
    );

    let result = scanner.scan(text).unwrap();

    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Email));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::PhoneNumber));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::CreditCard));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Iban));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::IpAddress));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Url));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::AwsAccessKey));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Jwt));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::ApiKey));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::MacAddress));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Hostname));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::UserPath));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::CryptoAddress));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::DateOfBirth));
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Ssn));

    let masked = result.masked_text.unwrap();
    assert!(masked.contains("[EMAIL]"));
    assert!(masked.contains("[PHONE]"));
    assert!(masked.contains("[CREDIT_CARD]"));
    assert!(masked.contains("[IBAN]"));
    assert!(masked.contains("[IP_ADDRESS]"));
    assert!(masked.contains("[URL]"));
    assert!(masked.contains("[AWS_KEY]"));
    assert!(masked.contains("[JWT]"));
    assert!(masked.contains("[API_KEY]"));
    assert!(masked.contains("[MAC_ADDR]"));
    assert!(masked.contains("[HOSTNAME]"));
    assert!(masked.contains("[USER_PATH]"));
    assert!(masked.contains("[CRYPTO_ADDR]"));
    assert!(masked.contains("[DOB]"));
    assert!(masked.contains("[SSN]"));
}

#[test]
fn test_scanner_with_universal_locale_excludes_us_ssn() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::Universal)
        .build()
        .unwrap();

    let result = scanner.scan("ssn: 123-45-6789").unwrap();
    assert!(result
        .findings
        .iter()
        .all(|finding| finding.entity_type != EntityType::Ssn));
}

#[test]
fn test_scanner_hash_strategy_masks_with_deterministic_hashes() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .strategy(MaskStrategy::Hash {
            salt: Some("test-salt".to_string()),
        })
        .build()
        .unwrap();

    let first = scanner.scan("email jane@example.com").unwrap();
    let second = scanner.scan("email jane@example.com").unwrap();

    let first_masked = first.masked_text.unwrap();
    let second_masked = second.masked_text.unwrap();
    assert_eq!(first_masked, second_masked);
    assert!(first_masked.starts_with("email HASH:"));
}

#[test]
fn test_scanner_min_confidence_filters_plain_ssn() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .min_confidence(0.8)
        .unwrap()
        .build()
        .unwrap();

    let result = scanner.scan("value 123456789").unwrap();
    assert!(result.findings.is_empty());
}

#[test]
fn test_scanner_replace_strategy_uses_fake_safe_values() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .strategy(MaskStrategy::Replace)
        .build()
        .unwrap();

    let result = scanner.scan("email jane@example.com").unwrap();
    let masked = result.masked_text.unwrap();

    assert!(masked.starts_with("email user"));
    assert!(masked.ends_with("@example.test"));
}

#[test]
fn test_scanner_encrypt_strategy_round_trips_email() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .strategy(MaskStrategy::Encrypt {
            key: TEST_KEY.to_string(),
        })
        .build()
        .unwrap();

    let result = scanner.scan("email jane@example.com").unwrap();
    let masked = result.masked_text.unwrap();
    let encrypted = masked.strip_prefix("email ").unwrap();

    assert!(encrypted.starts_with("ENC["));
    assert_eq!(
        decrypt_masked_value(encrypted, TEST_KEY).unwrap(),
        "jane@example.com"
    );
}

#[test]
fn test_scanner_encrypt_strategy_invalid_key_errors() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .strategy(MaskStrategy::Encrypt {
            key: "short".to_string(),
        })
        .build()
        .unwrap();

    assert!(scanner.scan("email jane@example.com").is_err());
}

#[test]
fn test_pipeline_stats_count_all_expected_entity_types() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .build()
        .unwrap();

    let result = scanner.scan(realistic_sprint_3_text()).unwrap();

    assert_eq!(result.stats.total_findings, 5);
    assert_eq!(result.stats.bytes_scanned, realistic_sprint_3_text().len());
    assert_eq!(result.stats.findings_by_type[&EntityType::Email], 1);
    assert_eq!(result.stats.findings_by_type[&EntityType::PhoneNumber], 1);
    assert_eq!(result.stats.findings_by_type[&EntityType::CreditCard], 1);
    assert_eq!(result.stats.findings_by_type[&EntityType::Iban], 1);
    assert_eq!(result.stats.findings_by_type[&EntityType::Ssn], 1);
}

#[test]
fn test_pipeline_all_masking_strategies_have_expected_output_shape() {
    let input = "email jane@example.com";
    let strategies = [
        MaskStrategy::Redact,
        MaskStrategy::PartialMask {
            reveal_prefix: 1,
            reveal_suffix: 0,
            mask_char: '*',
        },
        MaskStrategy::Hash {
            salt: Some("test-salt".to_string()),
        },
        MaskStrategy::Replace,
        MaskStrategy::Encrypt {
            key: TEST_KEY.to_string(),
        },
    ];

    let outputs: Vec<String> = strategies
        .into_iter()
        .map(|strategy| {
            default_registry()
                .into_scanner_builder()
                .locale(Locale::US)
                .strategy(strategy)
                .build()
                .unwrap()
                .scan(input)
                .unwrap()
                .masked_text
                .unwrap()
        })
        .collect();

    assert_eq!(outputs[0], "email [EMAIL]");
    assert_eq!(outputs[1], "email j***@example.com");
    assert!(outputs[2].starts_with("email HASH:"));
    assert!(outputs[3].starts_with("email user"));
    assert!(outputs[3].ends_with("@example.test"));
    assert!(outputs[4].starts_with("email ENC["));
}

#[test]
fn test_pipeline_locale_us_includes_ssn_while_universal_excludes_it() {
    let us = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .build()
        .unwrap()
        .scan("ssn: 123-45-6789")
        .unwrap();
    let universal = default_registry()
        .into_scanner_builder()
        .locale(Locale::Universal)
        .build()
        .unwrap()
        .scan("ssn: 123-45-6789")
        .unwrap();

    assert!(us
        .findings
        .iter()
        .any(|finding| finding.entity_type == EntityType::Ssn));
    assert!(universal
        .findings
        .iter()
        .all(|finding| finding.entity_type != EntityType::Ssn));
}

#[test]
#[ignore = "performance smoke test is intended for release-mode/manual runs"]
fn test_pipeline_scans_one_megabyte_under_budget_in_release_like_runs() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .without_masking()
        .build()
        .unwrap();
    let mut text = String::with_capacity(1024 * 1024);
    while text.len() < 1024 * 1024 {
        text.push_str(realistic_sprint_3_text());
        text.push('\n');
    }

    let started = Instant::now();
    let result = scanner.scan(&text).unwrap();

    assert!(result.stats.total_findings > 1000);
    assert!(
        started.elapsed().as_millis() < 100,
        "scan exceeded 100ms; run with --release before treating this as a regression"
    );
}

fn realistic_sprint_3_text() -> &'static str {
    concat!(
        "Please contact Jane at jane@example.com or call +1 (555) 123-4567. ",
        "Use test card 4111 1111 1111 1111 for billing validation. ",
        "Wire refunds to IBAN NL91ABNA0417164300. ",
        "Her SSN for the synthetic fixture is 123-45-6789."
    )
}

#[test]
fn test_scanner_random_byte_like_inputs_do_not_crash() {
    let scanner = default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .without_masking()
        .build()
        .unwrap();

    let mut state = 0xC10A_C10A_u64;
    for len in [0, 1, 2, 3, 8, 16, 31, 64, 127, 256, 1024] {
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((state >> 32) as u8);
        }
        let text = String::from_utf8_lossy(&bytes);
        let result = scanner.scan(&text);
        assert!(result.is_ok());
    }
}
