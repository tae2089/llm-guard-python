use serde::Deserialize;
use std::collections::HashMap;
use crate::detector::{PiiDetector, PiiPattern};

#[derive(Deserialize)]
pub struct Config {
    pub patterns: HashMap<String, PatternEntry>,
}

#[derive(Deserialize)]
pub struct PatternEntry {
    pub name: String,
    pub regex: String,
}

pub fn load_config(path: &str) -> Result<PiiDetector, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("설정 파일 읽기 실패: {}", e))?;
    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("설정 파일 파싱 실패: {}", e))?;

    let mut patterns = Vec::new();
    for (key, entry) in config.patterns {
        match regex::Regex::new(&entry.regex) {
            Ok(compiled) => {
                patterns.push(PiiPattern {
                    name: entry.name,
                    compiled,
                });
            }
            Err(e) => {
                eprintln!("[PII_GUARD] 경고: 패턴 '{}' 정규식 오류, 건너뜀: {}", key, e);
            }
        }
    }

    Ok(PiiDetector::new(patterns))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_valid_config() {
        let config = write_temp_config(r#"
[patterns]
[patterns.phone]
name = "전화번호"
regex = '01[016789]-?\d{3,4}-?\d{4}'
"#);
        let detector = load_config(config.path().to_str().unwrap()).unwrap();
        let result = detector.scan("010-1234-5678");
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern_name, "전화번호");
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config("/nonexistent/path.toml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("설정 파일 읽기 실패"));
    }

    #[test]
    fn test_load_config_invalid_regex_skipped() {
        let config = write_temp_config(r#"
[patterns]
[patterns.bad]
name = "잘못된패턴"
regex = '[invalid('

[patterns.good]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
"#);
        let detector = load_config(config.path().to_str().unwrap()).unwrap();
        let result = detector.scan("user@example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern_name, "이메일");
    }
}
