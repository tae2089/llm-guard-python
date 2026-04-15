#[derive(Debug)]
pub struct PiiPattern {
    pub name: String,
    pub compiled: regex::Regex,
}

#[derive(Debug)]
pub struct ScanMatch {
    pub pattern_name: String,
    pub matched_value: String,
}

#[derive(Debug)]
pub struct PiiDetector {
    patterns: Vec<PiiPattern>,
}

impl PiiDetector {
    pub fn new(patterns: Vec<PiiPattern>) -> Self {
        Self { patterns }
    }

    pub fn scan(&self, text: &str) -> Option<ScanMatch> {
        for pattern in &self.patterns {
            if let Some(m) = pattern.compiled.find(text) {
                return Some(ScanMatch {
                    pattern_name: pattern.name.clone(),
                    matched_value: m.as_str().to_string(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector_with_pattern(name: &str, pattern: &str) -> PiiDetector {
        let compiled = regex::Regex::new(pattern).unwrap();
        PiiDetector::new(vec![PiiPattern {
            name: name.to_string(),
            compiled,
        }])
    }

    #[test]
    fn test_detect_resident_id() {
        let detector = make_detector_with_pattern("주민등록번호", r"\d{6}-[1-4]\d{6}");
        let result = detector.scan("주민번호는 850101-1234567 입니다");
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.pattern_name, "주민등록번호");
        assert_eq!(m.matched_value, "850101-1234567");
    }

    #[test]
    fn test_no_resident_id_in_clean_text() {
        let detector = make_detector_with_pattern("주민등록번호", r"\d{6}-[1-4]\d{6}");
        let result = detector.scan("오늘 날씨가 좋습니다");
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_phone_number() {
        let detector = make_detector_with_pattern("전화번호", r"01[016789]-?\d{3,4}-?\d{4}");
        let result = detector.scan("연락처: 010-1234-5678");
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.pattern_name, "전화번호");
        assert_eq!(m.matched_value, "010-1234-5678");
    }

    #[test]
    fn test_detect_phone_number_no_dash() {
        let detector = make_detector_with_pattern("전화번호", r"01[016789]-?\d{3,4}-?\d{4}");
        let result = detector.scan("전화 01012345678");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_value, "01012345678");
    }

    #[test]
    fn test_detect_email() {
        let detector = make_detector_with_pattern("이메일", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}");
        let result = detector.scan("메일은 user@example.com 입니다");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_value, "user@example.com");
    }

    #[test]
    fn test_detect_credit_card() {
        let detector = make_detector_with_pattern("신용카드번호", r"\d{4}-?\d{4}-?\d{4}-?\d{4}");
        let result = detector.scan("카드: 1234-5678-9012-3456");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_value, "1234-5678-9012-3456");
    }

    #[test]
    fn test_detect_credit_card_no_dash() {
        let detector = make_detector_with_pattern("신용카드번호", r"\d{4}-?\d{4}-?\d{4}-?\d{4}");
        let result = detector.scan("카드 1234567890123456");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_value, "1234567890123456");
    }

    #[test]
    fn test_detect_bank_account() {
        let detector = make_detector_with_pattern("계좌번호", r"\d{3}-?\d{2,6}-?\d{2,6}-?\d{1,3}");
        let result = detector.scan("계좌: 110-123-456789-1");
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_passport() {
        let detector = make_detector_with_pattern("여권번호", r"[A-Z]{1}[0-9]{8}");
        let result = detector.scan("여권번호 M12345678");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_value, "M12345678");
    }

    #[test]
    fn test_no_false_positive_on_clean_text() {
        let detector = PiiDetector::new(vec![
            PiiPattern { name: "주민등록번호".to_string(), compiled: regex::Regex::new(r"\d{6}-[1-4]\d{6}").unwrap() },
            PiiPattern { name: "전화번호".to_string(), compiled: regex::Regex::new(r"01[016789]-?\d{3,4}-?\d{4}").unwrap() },
            PiiPattern { name: "이메일".to_string(), compiled: regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap() },
        ]);
        let result = detector.scan("오늘 회의는 3시에 있습니다. 참석자 5명.");
        assert!(result.is_none());
    }
}
