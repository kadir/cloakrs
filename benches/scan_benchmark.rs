use cloakrs_core::{Locale, MaskStrategy, Recognizer};
use cloakrs_patterns::{
    ApiKeyRecognizer, AwsAccessKeyRecognizer, CreditCardRecognizer, CryptoAddressRecognizer,
    DateOfBirthRecognizer, EmailRecognizer, IbanRecognizer, IpAddressRecognizer, JwtRecognizer,
    MacAddressRecognizer, PhoneRecognizer, SsnRecognizer, UrlRecognizer,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn bench_scan_sizes(c: &mut Criterion) {
    let scanner = cloakrs_locales::default_registry()
        .into_scanner_builder()
        .locale(Locale::US)
        .without_masking()
        .build()
        .expect("benchmark scanner should build");

    let mut group = c.benchmark_group("scan_input_sizes");
    for size in [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024] {
        for (kind, input) in [
            ("plain", fixture_plain(size)),
            ("json", fixture_json(size)),
            ("csv", fixture_csv(size)),
        ] {
            group.throughput(Throughput::Bytes(input.len() as u64));
            group.bench_with_input(BenchmarkId::new(kind, size), &input, |b, text| {
                b.iter(|| scanner.scan(black_box(text)).expect("scan should succeed"));
            });
        }
    }
    group.finish();
}

fn bench_recognizers(c: &mut Criterion) {
    let input = fixture_plain(32 * 1024);
    let mut group = c.benchmark_group("recognizers");

    macro_rules! recognizer_bench {
        ($name:literal, $recognizer:expr) => {
            group.bench_function($name, |b| {
                b.iter(|| $recognizer.scan(black_box(&input)));
            });
        };
    }

    recognizer_bench!("email", EmailRecognizer);
    recognizer_bench!("phone", PhoneRecognizer);
    recognizer_bench!("credit_card", CreditCardRecognizer);
    recognizer_bench!("iban", IbanRecognizer);
    recognizer_bench!("ssn", SsnRecognizer);
    recognizer_bench!("ip_address", IpAddressRecognizer);
    recognizer_bench!("url", UrlRecognizer);
    recognizer_bench!("aws_access_key", AwsAccessKeyRecognizer);
    recognizer_bench!("jwt", JwtRecognizer);
    recognizer_bench!("api_key", ApiKeyRecognizer);
    recognizer_bench!("mac_address", MacAddressRecognizer);
    recognizer_bench!("crypto_address", CryptoAddressRecognizer);
    recognizer_bench!("date_of_birth", DateOfBirthRecognizer);

    group.finish();
}

fn bench_masking_strategies(c: &mut Criterion) {
    let input = fixture_plain(32 * 1024);
    let mut group = c.benchmark_group("masking_strategies");

    for (name, strategy) in [
        ("redact", MaskStrategy::Redact),
        (
            "partial",
            MaskStrategy::PartialMask {
                reveal_prefix: 1,
                reveal_suffix: 4,
                mask_char: '*',
            },
        ),
        (
            "hash",
            MaskStrategy::Hash {
                salt: Some("benchmark".to_string()),
            },
        ),
        ("replace", MaskStrategy::Replace),
        (
            "encrypt",
            MaskStrategy::Encrypt {
                key: TEST_KEY.to_string(),
            },
        ),
    ] {
        let scanner = cloakrs_locales::default_registry()
            .into_scanner_builder()
            .locale(Locale::US)
            .strategy(strategy)
            .build()
            .expect("benchmark scanner should build");
        group.bench_function(name, |b| {
            b.iter(|| {
                scanner
                    .scan(black_box(&input))
                    .expect("scan should succeed")
            });
        });
    }

    group.finish();
}

fn fixture_plain(target_size: usize) -> String {
    let line = concat!(
        "email jane@example.com phone +1 (555) 123-4567 card 4111 1111 1111 1111 ",
        "iban NL91ABNA0417164300 ip 203.0.113.42 url https://example.com/path ",
        "aws AKIAIOSFODNN7EXAMPLE jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123456789_xyz ",
        "api_key=sk_live_0123456789abcdef mac 00:1A:2B:3C:4D:5E ",
        "wallet 0xde709f2102306220921060314715629080e2fb77 DOB 1980-04-23 ssn 123-45-6789\n",
    );
    repeat_to_size(line, target_size)
}

fn fixture_json(target_size: usize) -> String {
    let item = r#"{"email":"jane@example.com","phone":"+1 (555) 123-4567","token":"sk_live_0123456789abcdef","dob":"DOB 1980-04-23"},"#;
    let body = repeat_to_size(item, target_size.saturating_sub(16));
    format!(r#"{{"users":[{}]}}"#, body.trim_end_matches(','))
}

fn fixture_csv(target_size: usize) -> String {
    let row = "name,email,phone,token,dob\nJane,jane@example.com,+1 (555) 123-4567,sk_live_0123456789abcdef,DOB 1980-04-23\n";
    repeat_to_size(row, target_size)
}

fn repeat_to_size(unit: &str, target_size: usize) -> String {
    let mut output = String::with_capacity(target_size);
    while output.len() < target_size {
        output.push_str(unit);
    }
    output.truncate(target_size);
    output
}

criterion_group!(
    benches,
    bench_scan_sizes,
    bench_recognizers,
    bench_masking_strategies
);
criterion_main!(benches);
