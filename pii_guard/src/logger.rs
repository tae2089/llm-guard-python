use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;

pub fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 4 {
        return "*".repeat(len);
    }
    let visible = len / 3;
    let masked = len - visible;
    let prefix: String = chars[..visible].iter().collect();
    format!("{}{}", prefix, "*".repeat(masked))
}

pub struct Logger {
    path: String,
}

impl Logger {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn log(&self, method: &str, url: &str, pattern_name: &str, matched_value: &str) {
        let masked = mask_value(matched_value);
        let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S%z");
        let message = format!(
            "[{}] BLOCKED method={} url={} pattern={} matched={}",
            timestamp, method, url, pattern_name, masked
        );

        eprintln!("{}", message);

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_short_value() {
        assert_eq!(mask_value("abcd"), "****");
    }

    #[test]
    fn test_mask_resident_id() {
        let masked = mask_value("850101-1234567");
        assert_eq!(masked, "8501**********");
    }

    #[test]
    fn test_mask_phone() {
        let masked = mask_value("010-1234-5678");
        assert_eq!(masked, "010-*********");
    }

    #[test]
    fn test_mask_email() {
        let masked = mask_value("user@example.com");
        assert_eq!(masked, "user@***********");
    }

    #[test]
    fn test_log_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let logger = Logger::new(log_path.to_str().unwrap());

        logger.log("POST", "https://api.example.com/users", "전화번호", "010-1234-5678");

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("BLOCKED"));
        assert!(content.contains("method=POST"));
        assert!(content.contains("pattern=전화번호"));
        assert!(content.contains("010-*********"));
        assert!(!content.contains("010-1234-5678"));
    }
}
