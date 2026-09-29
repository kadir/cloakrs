//! Thin Python bridge: recognizers and redaction remain in cloakrs-core.

use cloakrs_core::{CloakError, EntityType, Locale, PiiEntity, Scanner};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyTuple;

const ENTITIES: &[(&str, EntityType)] = &[
    ("email", EntityType::Email),
    ("phone-number", EntityType::PhoneNumber),
    ("credit-card", EntityType::CreditCard),
    ("iban", EntityType::Iban),
    ("ip-address", EntityType::IpAddress),
    ("url", EntityType::Url),
    ("date-of-birth", EntityType::DateOfBirth),
    ("api-key", EntityType::ApiKey),
    ("jwt", EntityType::Jwt),
    ("aws-access-key", EntityType::AwsAccessKey),
    ("crypto-address", EntityType::CryptoAddress),
    ("mac-address", EntityType::MacAddress),
    ("hostname", EntityType::Hostname),
    ("user-path", EntityType::UserPath),
    ("person-name", EntityType::PersonName),
    ("physical-address", EntityType::PhysicalAddress),
    ("passport-number", EntityType::PassportNumber),
    ("drivers-license", EntityType::DriversLicense),
    ("ssn", EntityType::Ssn),
    ("bsn", EntityType::Bsn),
    ("nino", EntityType::Nino),
    ("nhs-number", EntityType::NhsNumber),
    ("aadhaar", EntityType::Aadhaar),
    ("pan", EntityType::Pan),
    ("cpf", EntityType::Cpf),
    ("cnpj", EntityType::Cnpj),
    ("steuer-id", EntityType::SteuerID),
    ("insee-nir", EntityType::InseeNir),
];

type NativeFinding = (String, usize, usize, f64, String, String);
type NativeScan = (String, Vec<NativeFinding>);

fn locale(value: &str) -> PyResult<Locale> {
    match value {
        "universal" => Ok(Locale::Universal),
        "us" => Ok(Locale::US),
        "uk" => Ok(Locale::UK),
        "nl" => Ok(Locale::NL),
        "de" => Ok(Locale::DE),
        "fr" => Ok(Locale::FR),
        "in" => Ok(Locale::IN),
        "br" => Ok(Locale::BR),
        "eu" => Ok(Locale::EU),
        _ => Err(PyValueError::new_err(
            "locale must be universal, us, uk, nl, de, fr, in, br, or eu",
        )),
    }
}

fn entity(value: &str) -> PyResult<EntityType> {
    ENTITIES
        .iter()
        .find(|(name, _)| *name == value)
        .map(|(_, entity)| entity.clone())
        .ok_or_else(|| {
            PyValueError::new_err("unknown excluded entity type; see cloakrs.ENTITY_TYPES")
        })
}

fn entity_name(entity: &EntityType) -> String {
    if let EntityType::Custom(name) = entity {
        // The bundled scanner only produces Custom for literal deny-list values.
        return if name == "DenyList" {
            "deny-list"
        } else {
            "custom"
        }
        .into();
    }
    ENTITIES
        .iter()
        .find(|(_, candidate)| candidate == entity)
        .map_or("unknown", |(name, _)| *name)
        .into()
}

fn scan_error(_: CloakError) -> PyErr {
    // Future engine errors may contain source values. Never echo them into Python.
    PyRuntimeError::new_err("the Rust scanner could not process the input")
}

/// Map only finding boundaries, using O(findings) memory rather than O(input bytes).
/// Sorting boundaries also handles nested findings whose ends are not ordered.
fn python_findings(
    text: &str,
    findings: Vec<PiiEntity>,
) -> cloakrs_core::Result<Vec<NativeFinding>> {
    let mut boundaries: Vec<_> = findings
        .iter()
        .flat_map(|f| [(f.span.start, 0), (f.span.end, 0)])
        .collect();
    if boundaries.is_empty() {
        return Ok(Vec::new());
    }
    boundaries.sort_unstable_by_key(|(byte, _)| *byte);
    boundaries.dedup_by_key(|(byte, _)| *byte);
    let mut cursor = 0;
    for (character, byte) in text
        .char_indices()
        .map(|(byte, _)| byte)
        .chain(std::iter::once(text.len()))
        .enumerate()
    {
        if boundaries[cursor].0 == byte {
            boundaries[cursor].1 = character;
            cursor += 1;
            if cursor == boundaries.len() {
                break;
            }
        }
    }
    if cursor != boundaries.len() {
        return Err(CloakError::InvalidSpan {
            start: boundaries[cursor].0,
            end: boundaries[cursor].0,
            len: text.len(),
        });
    }
    findings
        .into_iter()
        .map(|finding| {
            let index = |byte| {
                boundaries
                    .binary_search_by_key(&byte, |(offset, _)| *offset)
                    .map(|i| boundaries[i].1)
                    .map_err(|_| CloakError::InvalidSpan {
                        start: finding.span.start,
                        end: finding.span.end,
                        len: text.len(),
                    })
            };
            Ok((
                entity_name(&finding.entity_type),
                index(finding.span.start)?,
                index(finding.span.end)?,
                finding.confidence.value(),
                finding.recognizer_id,
                finding.text,
            ))
        })
        .collect()
}

#[pyclass(name = "_Scanner", module = "cloakrs._native", frozen)]
struct NativeScanner {
    inner: Scanner,
}

#[pymethods]
impl NativeScanner {
    #[new]
    #[pyo3(signature = (*, locale, min_confidence, exclude_entities, allow_list, deny_list))]
    fn new(
        py: Python<'_>,
        locale: &str,
        min_confidence: f64,
        exclude_entities: Vec<String>,
        allow_list: Vec<String>,
        deny_list: Vec<String>,
    ) -> PyResult<Self> {
        let selected_locale = self::locale(locale)?;
        let exclusions = exclude_entities
            .iter()
            .map(|name| entity(name))
            .collect::<PyResult<Vec<_>>>()?;
        cloakrs_core::Confidence::new(min_confidence).map_err(|_| {
            PyValueError::new_err("min_confidence must be finite and between 0 and 1")
        })?;
        let inner = py
            .detach(move || {
                cloakrs_locales::default_registry()
                    .into_scanner_builder()
                    .locale(selected_locale)
                    .min_confidence(min_confidence)?
                    .exclude_entities(exclusions)
                    .allow_list(allow_list)
                    .deny_list(deny_list)
                    .build()
            })
            .map_err(scan_error)?;
        Ok(Self { inner })
    }

    fn scan(&self, py: Python<'_>, text: String) -> PyResult<NativeScan> {
        py.detach(move || {
            let result = self.inner.scan(&text)?;
            let findings = python_findings(&text, result.findings)?;
            let masked = result.masked_text.ok_or_else(|| {
                CloakError::ConfigError("the Python scanner requires masking".into())
            })?;
            Ok((masked, findings))
        })
        .map_err(scan_error)
    }

    fn mask(&self, py: Python<'_>, text: String) -> PyResult<String> {
        py.detach(move || {
            self.inner.scan(&text).and_then(|result| {
                result.masked_text.ok_or_else(|| {
                    CloakError::ConfigError("the Python scanner requires masking".into())
                })
            })
        })
        .map_err(scan_error)
    }
}

// Free-threaded Python requires separate wheel and concurrency validation.
#[pymodule(gil_used = true)]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeScanner>()?;
    module.add("ENGINE_VERSION", cloakrs_locales::version())?;
    module.add(
        "ENTITY_TYPES",
        PyTuple::new(module.py(), ENTITIES.iter().map(|(name, _)| *name))?,
    )?;
    Ok(())
}
