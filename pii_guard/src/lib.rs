use pyo3::prelude::*;

mod config;
mod detector;
mod logger;

#[pymodule]
fn pii_guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(load_config, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(log, m)?)?;
    Ok(())
}

#[pyfunction]
fn load_config(_path: &str) -> PyResult<()> {
    Ok(())
}

#[pyfunction]
fn scan(_text: &str) -> PyResult<Option<String>> {
    Ok(None)
}

#[pyfunction]
fn log(_message: &str) -> PyResult<()> {
    Ok(())
}
