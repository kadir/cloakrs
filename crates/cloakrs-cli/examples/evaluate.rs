//! Evaluation adapter: emit typed byte spans without raw sensitive values.
//! See tests/evaluation/run.py for scoring, baseline checking, and measurements.
use cloakrs_core::{EntityType, Locale};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Instant;

#[derive(Deserialize)]
struct Corpus {
    min_confidence: f64,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    locale: Locale,
    text: String,
}

#[derive(Serialize)]
struct Finding {
    entity_type: EntityType,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct Prediction {
    id: String,
    findings: Vec<Finding>,
}

#[derive(Serialize)]
struct Output {
    predictions: Vec<Prediction>,
    first_pass_ms: f64,
    warm_scan_us: Vec<f64>,
    repetitions: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: evaluate CORPUS.json")?;
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(path)?)?;
    let started = Instant::now();
    let mut scanners = HashMap::new();
    let mut predictions = Vec::new();
    for case in &corpus.cases {
        if !scanners.contains_key(&case.locale) {
            let scanner = cloakrs_locales::default_registry()
                .into_scanner_builder()
                .locale(case.locale.clone())
                .min_confidence(corpus.min_confidence)?
                .without_masking()
                .build()?;
            scanners.insert(case.locale.clone(), scanner);
        }
        let result = scanners[&case.locale].scan(&case.text)?;
        predictions.push(Prediction {
            id: case.id.clone(),
            findings: result
                .findings
                .into_iter()
                .map(|finding| Finding {
                    entity_type: finding.entity_type,
                    start: finding.span.start,
                    end: finding.span.end,
                })
                .collect(),
        });
    }
    let first_pass_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let repetitions = 20;
    let mut warm_scan_us = Vec::new();
    for _ in 0..repetitions {
        for case in &corpus.cases {
            let before = Instant::now();
            std::hint::black_box(scanners[&case.locale].scan(std::hint::black_box(&case.text))?);
            warm_scan_us.push(before.elapsed().as_secs_f64() * 1_000_000.0);
        }
    }
    serde_json::to_writer(
        std::io::stdout(),
        &Output {
            predictions,
            first_pass_ms,
            warm_scan_us,
            repetitions,
        },
    )?;
    Ok(())
}
