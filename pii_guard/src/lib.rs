use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::sync::{Mutex, OnceLock};

mod config;
mod detector;
mod logger;
mod vectordb;
mod semantic;

use detector::PiiDetector;
use logger::Logger;
use semantic::SemanticAnalyzer;

static DETECTOR: OnceLock<PiiDetector> = OnceLock::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();
static ANALYZER: OnceLock<Mutex<SemanticAnalyzer>> = OnceLock::new();
static CONFIG_PATH: OnceLock<String> = OnceLock::new();

#[pyclass]
#[derive(Clone)]
struct ScanResult {
    #[pyo3(get)]
    pattern_name: String,
    #[pyo3(get)]
    matched_value: String,
}

#[pyclass]
#[derive(Clone)]
struct SemanticMatchResult {
    #[pyo3(get)]
    category: String,
    #[pyo3(get)]
    score: f32,
    #[pyo3(get)]
    matched_text: String,
}

#[pyfunction]
fn load_config(path: &str) -> PyResult<()> {
    CONFIG_PATH.set(path.to_string())
        .map_err(|_| PyRuntimeError::new_err("config path already set"))?;

    let detector = config::load_config(path)
        .map_err(|e| PyRuntimeError::new_err(e))?;
    DETECTOR.set(detector)
        .map_err(|_| PyRuntimeError::new_err("load_config already called"))?;

    let log_path = std::env::var("LLM_GUARD_LOG")
        .unwrap_or_else(|_| "llm_guard.log".to_string());
    LOGGER.set(Logger::new(&log_path))
        .map_err(|_| PyRuntimeError::new_err("logger already initialized"))?;

    Ok(())
}

#[pyfunction]
fn scan(text: &str) -> PyResult<Option<ScanResult>> {
    let detector = DETECTOR.get()
        .ok_or_else(|| PyRuntimeError::new_err("load_config not called"))?;

    Ok(detector.scan(text).map(|m| ScanResult {
        pattern_name: m.pattern_name,
        matched_value: m.matched_value,
    }))
}

#[pyfunction]
fn log_block(method: &str, url: &str, pattern_name: &str, matched_value: &str) -> PyResult<()> {
    let logger = LOGGER.get()
        .ok_or_else(|| PyRuntimeError::new_err("logger not initialized"))?;
    logger.log(method, url, pattern_name, matched_value);
    Ok(())
}

#[pyfunction]
fn get_semantic_config() -> PyResult<Option<PyObject>> {
    let config_path = CONFIG_PATH.get()
        .ok_or_else(|| PyRuntimeError::new_err("load_config not called"))?;

    if std::env::var("LLM_GUARD_SEMANTIC").unwrap_or_default() == "0" {
        return Ok(None);
    }

    let sc = config::load_semantic_config(config_path)
        .map_err(|e| PyRuntimeError::new_err(e))?;

    match sc {
        None => Ok(None),
        Some(sc) => Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("db_path", sc.db_path)?;
            dict.set_item("seed_path", sc.seed_path)?;
            dict.set_item("injection_threshold", sc.injection_threshold)?;
            dict.set_item("jailbreak_threshold", sc.jailbreak_threshold)?;
            Ok(Some(dict.unbind().into()))
        }),
    }
}

#[pyfunction]
fn init_semantic(db_path: &str, seed_path: &str, injection_threshold: f32, jailbreak_threshold: f32) -> PyResult<()> {
    let analyzer = SemanticAnalyzer::new(db_path, injection_threshold, jailbreak_threshold)
        .map_err(|e| PyRuntimeError::new_err(e))?;

    match config::load_seed_vectors(seed_path) {
        Ok(vectors) => {
            if let Err(e) = analyzer.seed_vectors(&vectors) {
                eprintln!("[LLM_GUARD] 시드 벡터 삽입 경고: {}", e);
            }
        }
        Err(e) => {
            eprintln!("[LLM_GUARD] 시드 파일 로드 경고: {}", e);
        }
    }

    ANALYZER.set(Mutex::new(analyzer))
        .map_err(|_| PyRuntimeError::new_err("init_semantic already called"))?;

    Ok(())
}

#[pyfunction]
fn analyze(text: &str) -> PyResult<Option<SemanticMatchResult>> {
    let mutex = match ANALYZER.get() {
        Some(m) => m,
        None => return Ok(None),
    };
    let analyzer = mutex.lock()
        .map_err(|e| PyRuntimeError::new_err(format!("analyzer lock failed: {}", e)))?;

    let result = analyzer.analyze(text)
        .map_err(|e| PyRuntimeError::new_err(e))?;

    match result {
        semantic::SemanticResult::Safe => Ok(None),
        semantic::SemanticResult::InjectionDetected { score, matched_text } => {
            Ok(Some(SemanticMatchResult {
                category: "injection".to_string(),
                score,
                matched_text,
            }))
        }
        semantic::SemanticResult::JailbreakDetected { score, matched_text } => {
            Ok(Some(SemanticMatchResult {
                category: "jailbreak".to_string(),
                score,
                matched_text,
            }))
        }
    }
}

#[pymodule]
fn _guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(load_config, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(log_block, m)?)?;
    m.add_function(wrap_pyfunction!(get_semantic_config, m)?)?;
    m.add_function(wrap_pyfunction!(init_semantic, m)?)?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_class::<ScanResult>()?;
    m.add_class::<SemanticMatchResult>()?;
    Ok(())
}
