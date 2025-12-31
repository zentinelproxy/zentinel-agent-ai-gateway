//! PII (Personally Identifiable Information) detection.
//!
//! Detects and optionally redacts sensitive data like emails, SSNs, phone numbers, and credit cards.

use regex::Regex;

/// Types of PII that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    Email,
    Ssn,
    PhoneNumber,
    CreditCard,
    IpAddress,
}

impl PiiType {
    /// Get the display name for this PII type
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiType::Email => "email",
            PiiType::Ssn => "ssn",
            PiiType::PhoneNumber => "phone",
            PiiType::CreditCard => "credit-card",
            PiiType::IpAddress => "ip-address",
        }
    }

    /// Get the redaction placeholder for this PII type
    pub fn redaction(&self) -> &'static str {
        match self {
            PiiType::Email => "[EMAIL REDACTED]",
            PiiType::Ssn => "[SSN REDACTED]",
            PiiType::PhoneNumber => "[PHONE REDACTED]",
            PiiType::CreditCard => "[CARD REDACTED]",
            PiiType::IpAddress => "[IP REDACTED]",
        }
    }
}

/// A match of PII in text
#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

/// Detector for personally identifiable information
pub struct PiiDetector {
    email_regex: Regex,
    ssn_regex: Regex,
    phone_regex: Regex,
    credit_card_regex: Regex,
    ip_regex: Regex,
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiDetector {
    /// Create a new PII detector
    pub fn new() -> Self {
        Self {
            email_regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .expect("Invalid email regex"),
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("Invalid SSN regex"),
            phone_regex: Regex::new(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
                .expect("Invalid phone regex"),
            credit_card_regex: Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
                .expect("Invalid credit card regex"),
            ip_regex: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            )
            .expect("Invalid IP regex"),
        }
    }

    /// Detect all PII in text
    pub fn detect(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        // Detect emails
        for m in self.email_regex.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Email,
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
            });
        }

        // Detect SSNs
        for m in self.ssn_regex.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Ssn,
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
            });
        }

        // Detect phone numbers
        for m in self.phone_regex.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::PhoneNumber,
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
            });
        }

        // Detect credit cards
        for m in self.credit_card_regex.find_iter(text) {
            // Basic Luhn check would be nice here but skip for simplicity
            matches.push(PiiMatch {
                pii_type: PiiType::CreditCard,
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
            });
        }

        // Detect IP addresses (skip common private ranges for less noise)
        for m in self.ip_regex.find_iter(text) {
            let ip = m.as_str();
            // Skip localhost and common private ranges
            if !ip.starts_with("127.")
                && !ip.starts_with("10.")
                && !ip.starts_with("192.168.")
                && !ip.starts_with("0.")
            {
                matches.push(PiiMatch {
                    pii_type: PiiType::IpAddress,
                    start: m.start(),
                    end: m.end(),
                    matched: ip.to_string(),
                });
            }
        }

        // Sort by position
        matches.sort_by_key(|m| m.start);
        matches
    }

    /// Check if text contains any PII
    pub fn has_pii(&self, text: &str) -> bool {
        self.email_regex.is_match(text)
            || self.ssn_regex.is_match(text)
            || self.phone_regex.is_match(text)
            || self.credit_card_regex.is_match(text)
    }

    /// Redact all PII in text
    pub fn redact(&self, text: &str) -> String {
        let matches = self.detect(text);
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for m in matches {
            result.push_str(&text[last_end..m.start]);
            result.push_str(m.pii_type.redaction());
            last_end = m.end;
        }

        result.push_str(&text[last_end..]);
        result
    }

    /// Get unique PII types found in text
    pub fn detect_types(&self, text: &str) -> Vec<PiiType> {
        let matches = self.detect(text);
        let mut types: Vec<PiiType> = matches.into_iter().map(|m| m.pii_type).collect();
        types.sort_by_key(|t| *t as u8);
        types.dedup();
        types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_email() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Contact me at john@example.com please");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Email);
        assert_eq!(matches[0].matched, "john@example.com");
    }

    #[test]
    fn test_detects_ssn() {
        let detector = PiiDetector::new();
        let matches = detector.detect("My SSN is 123-45-6789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Ssn);
    }

    #[test]
    fn test_detects_phone() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Call me at 555-123-4567");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::PhoneNumber);
    }

    #[test]
    fn test_detects_credit_card() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Card: 4111-1111-1111-1111");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::CreditCard);
    }

    #[test]
    fn test_redacts_pii() {
        let detector = PiiDetector::new();
        let redacted = detector.redact("Email: john@example.com, SSN: 123-45-6789");
        assert!(redacted.contains("[EMAIL REDACTED]"));
        assert!(redacted.contains("[SSN REDACTED]"));
        assert!(!redacted.contains("john@example.com"));
        assert!(!redacted.contains("123-45-6789"));
    }

    #[test]
    fn test_no_pii() {
        let detector = PiiDetector::new();
        let matches = detector.detect("Hello, how are you today?");
        assert!(matches.is_empty());
    }
}
