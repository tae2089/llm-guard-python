pub struct PiiPattern {
    pub name: String,
    pub compiled: regex::Regex,
}

pub struct ScanMatch {
    pub pattern_name: String,
    pub matched_value: String,
}

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
}
