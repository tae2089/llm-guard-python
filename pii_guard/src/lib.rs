use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::sync::OnceLock;

mod config;
mod detector;
mod logger;

use detector::PiiDetector;
use logger::Logger;

static DETECTOR: OnceLock<PiiDetector> = OnceLock::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();

#[pyclass]
#[derive(Clone)]
struct ScanResult {
    #[pyo3(get)]
    pattern_name: String,
    #[pyo3(get)]
    matched_value: String,
}

#[pyfunction]
fn load_config(path: &str) -> PyResult<()> {
    let detector = config::load_config(path)
        .map_err(|e| PyRuntimeError::new_err(e))?;
    DETECTOR.set(detector)
        .map_err(|_| PyRuntimeError::new_err("load_config already called"))?;

    let log_path = std::env::var("PII_GUARD_LOG")
        .unwrap_or_else(|_| "pii_guard.log".to_string());
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

#[pymodule]
fn pii_guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(load_config, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(log_block, m)?)?;
    m.add_class::<ScanResult>()?;
    Ok(())
}
