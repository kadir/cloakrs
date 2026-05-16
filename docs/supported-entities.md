# Supported Entities

cloakrs ships rule-based recognizers with explicit validators where the identifier has a public checksum or structural algorithm. Confidence scores are clamped to `0.0..=1.0`; context words can raise the score when nearby labels make the match less ambiguous.

The `Locale` column shows where the recognizer is active. `Universal` recognizers run for every locale.

| Entity type | Locale | Recognizer ID | Detection method | Validation algorithm | Confidence range | Example |
| --- | --- | --- | --- | --- | --- | --- |
| `Email` | Universal | `email_regex_v1` | RFC-like email regex with support for quoted local parts, plus tags, and subdomains | Rejects missing TLDs, URL-embedded addresses, malformed domains, at-mentions, and invalid local/domain shapes | `0.85` to `1.00` | `jane.doe+alerts@example.com` |
| `PhoneNumber` | Universal | `phone_regex_v1` | International, NANP, and common mobile/landline regex patterns | Digit-count checks, repeated-digit rejection, year/ZIP suppression, and card-like sequence rejection | `0.70` to `1.00` | `+44 7911 123456` |
| `CreditCard` | Universal | `credit_card_luhn_v1` | 13 to 19 digit candidates with spaces, dashes, or dots | Luhn checksum plus brand-family classification for Visa, Mastercard, Amex, and Discover | `0.60` to `0.99` | `4111 1111 1111 1111` |
| `Iban` | Universal | `iban_mod97_v1` | Two-letter country code plus alphanumeric IBAN body, with optional spaces | Country-specific length table and ISO 13616 MOD-97 checksum | `0.85` to `1.00` | `NL91 ABNA 0417 1643 00` |
| `Ssn` | US | `us_ssn_regex_v1`; `url_query_ssn_v1` | Dashed, spaced, and plain 9-digit SSNs; URL-query values when locale is US | Rejects invalid area, group, and serial ranges, including `000`, `666`, `900-999`, `00`, and `0000` | `0.55` to `1.00` | `123-45-6789` |
| `IpAddress` | Universal | `ip_address_std_v1` | IPv4 dotted decimal and IPv6 colon-hex candidates | Parsed with `std::net::IpAddr`; rejects embedded partial matches and invalid octets/shapes | `0.72` to `1.00` | `2001:db8::1` |
| `Url` | Universal | `url_regex_v1` | `http://`, `https://`, `ftp://`, and `www.` URL patterns | Host validation for domains, `localhost`, and IP hosts; trailing punctuation trimming; balanced-parentheses handling | `0.78` to `1.00` | `https://example.com/profile?id=42` |
| `DateOfBirth` | Universal | `date_of_birth_context_v1` | ISO, slash/dash numeric dates, and month-name date patterns near birth-date context | Calendar validation, leap-year handling, boundary checks, and required DOB/birth context | `0.76` to `1.00` | `DOB 1990-04-17` |
| `ApiKey` | Universal | `api_key_context_v1` | Long token candidates introduced by labels such as `api_key`, `token`, `secret`, or `authorization` | Minimum length, mixed-character checks, repeated-value rejection, and context requirement | `0.82` to `1.00` | `api_key=sk_live_51H8abcDEF1234567890xyz` |
| `Jwt` | Universal | `jwt_regex_v1` | Three base64url-like dot-separated JWT segments | Segment count, segment length, base64url character set, and version-string suppression | `0.92` to `1.00` | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` |
| `AwsAccessKey` | Universal | `aws_access_key_v1` | AWS access key ID pattern | `AKIA` prefix plus 16 uppercase alphanumeric characters and boundary checks | `0.99` to `1.00` | `AKIAIOSFODNN7EXAMPLE` |
| `CryptoAddress` | Universal | `crypto_address_regex_v1` | Ethereum and Bitcoin legacy/script/bech32 address patterns | Hex validation for Ethereum, base58 alphabet checks for legacy Bitcoin, and bech32 case rules | `0.82` to `1.00` | `0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe` |
| `MacAddress` | Universal | `mac_address_regex_v1` | Colon, hyphen, and dotted MAC address formats | Hex-octet validation, separator consistency, and embedded-boundary rejection | `0.82` to `1.00` | `00:1A:2B:3C:4D:5E` |
| `Hostname` | Universal | `hostname_infra_v1` | Internal DNS names, cloud infrastructure hostnames, mDNS names, and Windows machine names | Host label validation plus suppression of regular public domains, email domains, URLs, reversed Java-style domains, and single-word hosts | `0.50` to `1.00` | `db-prod-01.internal.company.com` |
| `UserPath` | Universal | `user_path_home_v1` | Linux, macOS, Windows, and root home-directory paths containing usernames | Username extraction with placeholder username suppression and system-path/relative-path avoidance | `0.75` to `1.00` | `/home/kadir/.ssh/id_rsa` |
| `Bsn` | NL, EU | `nl_bsn_mod11_v1` | Dutch 9-digit BSN candidates | Dutch 11-check checksum with low no-context confidence | `0.35` to `1.00` | `123456782` |
| `Nino` | UK | `uk_nino_regex_v1` | UK National Insurance number patterns with compact or spaced formatting | Prefix-letter rules, forbidden prefix combinations, six-digit body, and A-D suffix | `0.75` to `1.00` | `QQ 12 34 56 C` |
| `NhsNumber` | UK | `uk_nhs_number_mod11_v1` | UK NHS numbers in compact, spaced, or hyphenated form | NHS Modulus 11 check digit algorithm | `0.70` to `1.00` | `943 476 5919` |
| `Aadhaar` | IN | `in_aadhaar_verhoeff_v1` | Indian Aadhaar numbers in compact, spaced, or hyphenated form | Verhoeff checksum plus leading `0` / `1` rejection | `0.65` to `1.00` | `2345 6789 0120` |
| `Pan` | IN | `in_pan_regex_v1` | Indian PAN structure `AAAAA9999A` | Holder-type code validation and non-zero numeric sequence check | `0.78` to `1.00` | `ABCDE1234F` |
| `Cpf` | BR | `br_cpf_mod11_v1` | Brazilian CPF in compact or `###.###.###-##` form | Two-digit weighted MOD-11 checksum and repeated-digit rejection | `0.65` to `1.00` | `529.982.247-25` |
| `Cnpj` | BR | `br_cnpj_mod11_v1` | Brazilian CNPJ in compact or `##.###.###/####-##` form | Two-digit weighted MOD-11 checksum and repeated-digit rejection | `0.70` to `1.00` | `04.252.011/0001-10` |
| `SteuerID` | DE, EU | `de_steuer_id_mod11_10_v1` | German 11-digit Steuer-ID / Identifikationsnummer candidates | Required digit distribution, leading-zero rejection, and MOD 11,10 check digit | `0.55` to `1.00` | `86095742791` |
| `InseeNir` | FR, EU | `fr_insee_nir_mod97_v1` | French NIR / social security numbers in compact, spaced, or hyphenated form | 13-character NIR plus 2-digit complement-to-97 key, including Corsica `2A` / `2B` handling | `0.65` to `1.00` | `1 84 12 76 451 089 46` |
| `Custom(String)` | User-defined | User-defined | Provided by third-party recognizers implementing `Recognizer` | Provided by the custom recognizer | User-defined | `customer_id: CUS-12345` |

## Nested URL Findings

URL query scanning can emit additional findings inside a URL:

- `url_query_email_v1` reports `Email` for query values such as `?email=jane%40example.com`.
- `url_query_ssn_v1` reports `Ssn` for query values such as `?ssn=123-45-6789` when scanning with `Locale::US`.

The scanner keeps those nested findings in reports while masking the outer URL once, so replacements do not corrupt overlapping spans.

## Reserved Entity Variants

`PassportNumber` and `DriversLicense` are reserved in `cloakrs-core::EntityType` for future recognizers. They are not registered by `cloakrs-patterns::default_registry()` or `cloakrs-locales::default_registry()` in the current release.
