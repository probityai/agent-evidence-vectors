//! The Python exception types, and the one conversion every refusal goes through.
//!
//! Each crate serializes its own error as `{"variant": ..., "fields": ...}`
//! (serde's adjacently tagged form). The exception carries that pair as
//! `variant` and `fields`, unchanged, beside the crate's own `Display` text, so
//! the mapping is the crate's and not a second copy of it maintained here. A
//! variant the crate adds later arrives with its own name and fields without a
//! change to this file.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::Serialize;
use serde_json::Value;

pyo3::create_exception!(
    jcs_admit,
    JcsError,
    PyValueError,
    "A refusal from jcs-admit. `variant` is the Rust variant name and `fields` its fields, unchanged."
);

pyo3::create_exception!(
    jcs_admit.dsse,
    DsseError,
    PyValueError,
    "A refusal from dsse. `variant` is the Rust variant name and `fields` its fields, unchanged."
);

/// Builds the exception for one native refusal.
///
/// `fields` is a dict for a struct variant, the bare value for a one-field tuple
/// variant, and `None` for a unit variant: the three shapes serde writes, kept as
/// written so every binding of the crate reports the same data.
pub(crate) fn refusal<E, T>(py: Python<'_>, error: &E) -> PyErr
where
    E: Serialize + std::fmt::Display,
    T: pyo3::type_object::PyTypeInfo,
{
    let message = error.to_string();
    let tagged = match serde_json::to_value(error) {
        Ok(value) => value,
        Err(e) => {
            return PyRuntimeError::new_err(format!(
                "could not serialize the native refusal ({e}): {message}"
            ))
        }
    };
    let variant = match tagged.get("variant").and_then(Value::as_str) {
        Some(name) => name.to_owned(),
        None => {
            return PyRuntimeError::new_err(format!(
                "the native refusal serialized without a variant name: {message}"
            ))
        }
    };
    let err = PyErr::from_type(T::type_object(py), (message,));
    let attached = to_python(py, tagged.get("fields").unwrap_or(&Value::Null)).and_then(|fields| {
        let instance = err.value(py);
        instance.setattr("variant", variant)?;
        instance.setattr("fields", fields)
    });
    match attached {
        Ok(()) => err,
        Err(e) => e,
    }
}

/// Converts the JSON a refusal serialized to into the matching Python value.
fn to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => u.into_pyobject(py)?.into_any(),
            (None, Some(i)) => i.into_pyobject(py)?.into_any(),
            (None, None) => n.as_f64().unwrap_or(f64::NAN).into_pyobject(py)?.into_any(),
        },
        Value::String(s) => s.into_pyobject(py)?.into_any(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_python(py, item)?)?;
            }
            list.into_any()
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, to_python(py, item)?)?;
            }
            dict.into_any()
        }
    })
}
