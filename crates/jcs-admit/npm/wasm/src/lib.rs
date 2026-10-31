//! Raw byte bindings. Admission and canonicalization remain in the Rust core.

use js_sys::{Reflect, TypeError, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Admit raw JSON bytes under the unchanged RFC 8785 default profile.
#[wasm_bindgen]
pub fn admit(input: JsValue) -> Result<Uint8Array, JsValue> {
    run(input, &jcs_admit::Options::rfc8785())
}

/// Admit raw JSON bytes under the explicit RFC 7493 I-JSON tightening.
#[wasm_bindgen]
pub fn admit_ijson(input: JsValue) -> Result<Uint8Array, JsValue> {
    run(input, &jcs_admit::Options::ijson())
}

fn run(input: JsValue, opts: &jcs_admit::Options) -> Result<Uint8Array, JsValue> {
    let input = input
        .dyn_into::<Uint8Array>()
        .map_err(|_| TypeError::new("input must be a Uint8Array"))?;
    if let Err(error) = opts.check_input_length(input.length() as usize) {
        return Err(error_payload(&error)?);
    }
    let bytes = input.to_vec();
    match jcs_admit::admit_with(&bytes, opts) {
        Ok(output) => Ok(Uint8Array::from(output.as_slice())),
        Err(error) => Err(error_payload(&error)?),
    }
}

fn error_payload(error: &jcs_admit::Error) -> Result<JsValue, JsValue> {
    // Derive the discriminant and every field from the native enum. This avoids
    // maintaining another refusal list or translating the native reason text.
    let payload =
        serde_wasm_bindgen::to_value(error).map_err(|e| js_sys::Error::new(&e.to_string()))?;
    Reflect::set(
        &payload,
        &JsValue::from_str("message"),
        &JsValue::from_str(&error.to_string()),
    )?;
    Ok(payload)
}
