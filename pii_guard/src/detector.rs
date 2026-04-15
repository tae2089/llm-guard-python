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

    pub fn scan(&self, _text: &str) -> Option<ScanMatch> {
        None
    }
}
