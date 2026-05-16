use crate::common::{compile_regex, confidence, context_boost};
use cloakrs_core::{Confidence, EntityType, Locale, PiiEntity, Recognizer, Span};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static UNIX_HOME_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(r#"(?:/home/|/Users/)([a-zA-Z][a-zA-Z0-9._-]{0,31})(/[^\s:"'`,;)}\]]*)*"#)
});

static WINDOWS_HOME_REGEX: Lazy<Regex> = Lazy::new(|| {
    compile_regex(r#"(?i)[A-Z]:\\Users\\([a-zA-Z][a-zA-Z0-9._\- ]{0,31})(\\[^\s:"'`,;)}\]]*)*"#)
});

static ROOT_PATH_REGEX: Lazy<Regex> = Lazy::new(|| compile_regex(r#"/root(/[^\s:"'`,;)}\]]*)*"#));

const IGNORE_USERNAMES: &[&str] = &[
    "user",
    "username",
    "example",
    "your_user",
    "your_username",
    "yourusername",
    "myuser",
    "testuser",
    "$user",
    "{user}",
    "xxx",
    "placeholder",
];

const CONTEXT_WORDS: &[&str] = &[
    "file",
    "path",
    "directory",
    "folder",
    "config",
    "open",
    "read",
    "write",
    "permission",
    "denied",
    "not found",
    "no such file",
    "filenotfounderror",
    "enoent",
    "stack trace",
    "at /",
    "from /",
    "in /",
];

const SENSITIVE_SUBPATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".env",
    "credentials",
    ".gnupg",
    "id_rsa",
    "authorized_keys",
];

/// Recognizes home-directory paths that expose system usernames.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{EntityType, Recognizer};
/// use cloakrs_patterns::UserPathRecognizer;
///
/// let findings = UserPathRecognizer.scan("open /home/kadir/.ssh/id_rsa");
/// assert_eq!(findings[0].entity_type, EntityType::UserPath);
/// assert_eq!(UserPathRecognizer::extract_username("/home/kadir/.ssh/id_rsa").as_deref(), Some("kadir"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct UserPathRecognizer;

impl Recognizer for UserPathRecognizer {
    fn id(&self) -> &str {
        "user_path_home_v1"
    }

    fn entity_type(&self) -> EntityType {
        EntityType::UserPath
    }

    fn supported_locales(&self) -> &[Locale] {
        &[]
    }

    fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for regex in [&*UNIX_HOME_REGEX, &*WINDOWS_HOME_REGEX, &*ROOT_PATH_REGEX] {
            for matched in regex.find_iter(text) {
                let span = trim_path_span(text, Span::new(matched.start(), matched.end()));
                if span.is_empty() || !seen.insert((span.start, span.end)) {
                    continue;
                }
                let candidate = &text[span.start..span.end];
                if self.is_valid_path_match(text, span.start, span.end, candidate) {
                    findings.push(PiiEntity {
                        entity_type: self.entity_type(),
                        span,
                        text: candidate.to_string(),
                        confidence: self.compute_confidence(text, span.start, candidate),
                        recognizer_id: self.id().to_string(),
                    });
                }
            }
        }

        findings.sort_by_key(|finding| finding.span.start);
        findings
    }

    fn validate(&self, candidate: &str) -> bool {
        Self::extract_username(candidate).is_some_and(|username| !is_ignored_username(&username))
    }
}

impl UserPathRecognizer {
    /// Extracts the username segment from a supported home-directory path.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloakrs_patterns::UserPathRecognizer;
    ///
    /// assert_eq!(UserPathRecognizer::extract_username("/Users/john/Documents").as_deref(), Some("john"));
    /// assert_eq!(UserPathRecognizer::extract_username(r"C:\Users\john.doe\Desktop").as_deref(), Some("john.doe"));
    /// ```
    #[must_use]
    pub fn extract_username(path: &str) -> Option<String> {
        if let Some(rest) = path.strip_prefix("/home/") {
            return first_unix_segment(rest);
        }
        if let Some(rest) = path.strip_prefix("/Users/") {
            return first_unix_segment(rest);
        }
        let lower = path.to_ascii_lowercase();
        if let Some(index) = lower.find(r"\users\") {
            let after = &path[index + r"\Users\".len()..];
            return after.split('\\').next().map(str::to_string);
        }
        if path == "/root" || path.starts_with("/root/") {
            return Some("root".to_string());
        }
        None
    }

    fn is_valid_path_match(&self, text: &str, start: usize, end: usize, candidate: &str) -> bool {
        self.validate(candidate) && is_path_boundary(text, start, end)
    }

    fn compute_confidence(&self, text: &str, start: usize, candidate: &str) -> Confidence {
        let base = if candidate == "/root" || candidate.starts_with("/root/") {
            0.75
        } else {
            0.85
        };
        let sensitive_boost = if contains_sensitive_subpath(candidate) {
            0.05
        } else {
            0.0
        };
        confidence(base + sensitive_boost + context_boost(text, start, CONTEXT_WORDS))
    }
}

fn first_unix_segment(rest: &str) -> Option<String> {
    rest.split('/').next().map(str::to_string)
}

fn is_ignored_username(username: &str) -> bool {
    let lower = username.to_ascii_lowercase();
    IGNORE_USERNAMES.contains(&lower.as_str())
}

fn contains_sensitive_subpath(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SENSITIVE_SUBPATHS
        .iter()
        .any(|subpath| lower.contains(subpath))
}

fn trim_path_span(text: &str, span: Span) -> Span {
    let mut end = span.end;
    while end > span.start {
        let value = &text[span.start..end];
        let Some(c) = value.chars().next_back() else {
            break;
        };
        if !matches!(c, '.' | ',' | ':' | ';' | '!' | '?' | ')' | ']' | '}') {
            break;
        }
        end -= c.len_utf8();
    }
    Span::new(span.start, end)
}

fn is_path_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_path_continuation) && !after.is_some_and(is_path_continuation)
}

fn is_path_continuation(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '\\')
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakrs_core::RecognizerRegistry;

    fn texts(input: &str) -> Vec<String> {
        UserPathRecognizer
            .scan(input)
            .into_iter()
            .map(|finding| finding.text)
            .collect()
    }

    #[test]
    fn test_user_path_home_project_detected() {
        assert_eq!(
            texts("open /home/kadir/projects/myapp/config.yml"),
            ["/home/kadir/projects/myapp/config.yml"]
        );
    }

    #[test]
    fn test_user_path_linux_ssh_key_detected() {
        assert_eq!(
            texts("read /home/ubuntu/.ssh/id_rsa"),
            ["/home/ubuntu/.ssh/id_rsa"]
        );
    }

    #[test]
    fn test_user_path_linux_env_file_detected() {
        assert_eq!(texts("config /home/deploy/.env"), ["/home/deploy/.env"]);
    }

    #[test]
    fn test_user_path_macos_document_detected() {
        assert_eq!(
            texts("file /Users/john/Documents/report.pdf"),
            ["/Users/john/Documents/report.pdf"]
        );
    }

    #[test]
    fn test_user_path_macos_aws_credentials_detected() {
        assert_eq!(
            texts("path /Users/admin/.aws/credentials"),
            ["/Users/admin/.aws/credentials"]
        );
    }

    #[test]
    fn test_user_path_windows_administrator_detected() {
        assert_eq!(
            texts(r"open C:\Users\Administrator\Desktop\secrets.txt"),
            [r"C:\Users\Administrator\Desktop\secrets.txt"]
        );
    }

    #[test]
    fn test_user_path_windows_dotted_username_detected() {
        assert_eq!(
            texts(r"temp C:\Users\john.doe\AppData\Local\Temp"),
            [r"C:\Users\john.doe\AppData\Local\Temp"]
        );
    }

    #[test]
    fn test_user_path_root_bashrc_detected() {
        assert_eq!(texts("file /root/.bashrc"), ["/root/.bashrc"]);
    }

    #[test]
    fn test_user_path_root_authorized_keys_detected() {
        assert_eq!(
            texts("read /root/.ssh/authorized_keys"),
            ["/root/.ssh/authorized_keys"]
        );
    }

    #[test]
    fn test_user_path_usr_local_rejected() {
        assert!(texts("path /usr/local/bin/python").is_empty());
    }

    #[test]
    fn test_user_path_var_log_rejected() {
        assert!(texts("path /var/log/syslog").is_empty());
    }

    #[test]
    fn test_user_path_etc_nginx_rejected() {
        assert!(texts("path /etc/nginx/nginx.conf").is_empty());
    }

    #[test]
    fn test_user_path_relative_config_rejected() {
        assert!(texts("path ./config/settings.yml").is_empty());
    }

    #[test]
    fn test_user_path_placeholder_user_rejected() {
        assert!(texts("example /home/user/example").is_empty());
    }

    #[test]
    fn test_user_path_container_app_rejected() {
        assert!(texts("path /app/src/main.rs").is_empty());
    }

    #[test]
    fn test_user_path_filenotfound_context_boosts_confidence() {
        let with_context =
            UserPathRecognizer.scan("FileNotFoundError: /home/kadir/.config/app.yml");
        let without_context = UserPathRecognizer.scan("value /home/kadir/.config/app.yml");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_user_path_permission_denied_context_boosts_confidence() {
        let with_context = UserPathRecognizer.scan("permission denied: /Users/admin/private");
        let without_context = UserPathRecognizer.scan("value /Users/admin/private");
        assert!(with_context[0].confidence > without_context[0].confidence);
    }

    #[test]
    fn test_user_path_extract_username_from_linux_home() {
        assert_eq!(
            UserPathRecognizer::extract_username("/home/kadir/stuff").as_deref(),
            Some("kadir")
        );
    }

    #[test]
    fn test_user_path_extract_username_from_windows_home() {
        assert_eq!(
            UserPathRecognizer::extract_username(r"C:\Users\john.doe\Desktop").as_deref(),
            Some("john.doe")
        );
    }

    #[test]
    fn test_user_path_extract_username_from_root_home() {
        assert_eq!(
            UserPathRecognizer::extract_username("/root/.ssh").as_deref(),
            Some("root")
        );
    }

    #[test]
    fn test_user_path_sensitive_subpath_boosts_confidence() {
        let sensitive = UserPathRecognizer.scan("value /home/kadir/.ssh/id_rsa");
        let ordinary = UserPathRecognizer.scan("value /home/kadir/projects/app");
        assert!(sensitive[0].confidence > ordinary[0].confidence);
    }

    #[test]
    fn test_user_path_supported_locales_are_universal() {
        assert!(UserPathRecognizer.supported_locales().is_empty());
    }

    #[test]
    fn test_user_path_registry_integration_detects_default_recognizer() {
        let mut registry = RecognizerRegistry::new();
        crate::register_default_recognizers(&mut registry);

        let findings = registry.scan_all("open /home/kadir/projects/app");

        assert!(findings
            .iter()
            .any(|finding| finding.entity_type == EntityType::UserPath));
    }
}
