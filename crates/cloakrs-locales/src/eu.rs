//! European Union meta-locale support.

use cloakrs_core::Locale;

pub(crate) static DE_AND_EU_LOCALES: &[Locale] = &[Locale::DE, Locale::EU];
pub(crate) static FR_AND_EU_LOCALES: &[Locale] = &[Locale::FR, Locale::EU];
pub(crate) static NL_AND_EU_LOCALES: &[Locale] = &[Locale::NL, Locale::EU];

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::EntityType;

    #[test]
    fn test_eu_locale_includes_eu_country_recognizers() {
        let registry = crate::default_registry();
        let findings = registry.scan_locale(
            "BSN 123456782 Steuer-ID 48954371207 NIR 151024610204325",
            &Locale::EU,
        );
        let entity_types = findings
            .into_iter()
            .map(|finding| finding.entity_type)
            .collect::<Vec<_>>();

        assert!(entity_types.contains(&EntityType::Bsn));
        assert!(entity_types.contains(&EntityType::SteuerID));
        assert!(entity_types.contains(&EntityType::InseeNir));
    }

    #[test]
    fn test_eu_locale_includes_universal_iban() {
        let registry = crate::default_registry();
        let findings = registry.scan_locale("IBAN DE89 3704 0044 0532 0130 00", &Locale::EU);

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Iban));
    }

    #[test]
    fn test_eu_locale_excludes_non_eu_country_recognizers() {
        let registry = crate::default_registry();
        let findings = registry.scan_locale(
            "NINO AB 12 34 56 C Aadhaar 2345 6789 0124 CPF 529.982.247-25",
            &Locale::EU,
        );

        assert!(!findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Nino));
        assert!(!findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Aadhaar));
        assert!(!findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::Cpf));
    }
}
