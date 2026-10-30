//! The native DSSE implementation owns parsing, thresholds and verified bytes.

use dsse::{Ed25519Verifier, Verifier};
use js_sys::{Array, Object, Reflect, TypeError, Uint8Array};
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKey {
    public_key: Vec<u8>,
    key_id: Option<String>,
}

fn raw_bytes(value: JsValue) -> Result<Vec<u8>, JsValue> {
    let bytes = value
        .dyn_into::<Uint8Array>()
        .map_err(|_| TypeError::new("input must be a Uint8Array"))?;
    Ok(bytes.to_vec())
}

fn set(object: &JsValue, key: &str, value: &JsValue) -> Result<(), JsValue> {
    if !Reflect::set(object, &JsValue::from_str(key), value)? {
        return Err(js_sys::Error::new("could not construct the result").into());
    }
    Ok(())
}

fn refusal(error: dsse::Error) -> JsValue {
    // The native enum supplies the discriminant and every field. Unit variants
    // have no fields member; tuple variants keep their original string value.
    let result = (|| {
        let value = serde_wasm_bindgen::to_value(&error)
            .map_err(|error| js_sys::Error::new(&error.to_string()))?;
        set(&value, "message", &JsValue::from_str(&error.to_string()))?;
        Ok::<_, JsValue>(value)
    })();
    match result {
        Ok(value) => value,
        Err(error) => error,
    }
}

/// Verify a raw DSSE envelope using the native Ed25519 backend and threshold.
///
/// The returned payload comes only from `dsse::verify`, never a second parse.
#[wasm_bindgen]
pub fn verify(
    envelope: JsValue,
    trusted_keys: JsValue,
    threshold: u32,
) -> Result<JsValue, JsValue> {
    let bytes = raw_bytes(envelope)?;
    let envelope = dsse::Envelope::from_json(&bytes).map_err(refusal)?;
    // Parsed members are owned. Free the raw copy before signature work.
    drop(bytes);
    let inputs: Vec<TrustedKey> = serde_wasm_bindgen::from_value(trusted_keys)
        .map_err(|_| TypeError::new("trusted_keys has an invalid transport shape"))?;
    let mut keys = Vec::with_capacity(inputs.len());
    for input in inputs {
        let key = Ed25519Verifier::from_bytes(&input.public_key).map_err(refusal)?;
        keys.push(match input.key_id {
            Some(id) => key.with_key_id(id),
            None => key,
        });
    }
    let references: Vec<&dyn Verifier> = keys.iter().map(|key| key as &dyn Verifier).collect();
    let verified = dsse::verify(&envelope, &references, threshold as usize).map_err(refusal)?;
    let result = Object::new();
    set(
        &result,
        "payload_type",
        &JsValue::from_str(&verified.payload_type),
    )?;
    set(
        &result,
        "payload",
        &Uint8Array::from(verified.payload.as_slice()),
    )?;
    let accepted = Array::new();
    for id in verified.accepted_keys {
        accepted.push(&JsValue::from_str(&id));
    }
    set(&result, "accepted_keys", &accepted)?;
    Ok(result.into())
}

/// Return the native pre-authentication encoding. This does not verify a signature.
#[wasm_bindgen]
pub fn pae(payload_type: &str, payload: JsValue) -> Result<Uint8Array, JsValue> {
    let payload = raw_bytes(payload)?;
    Ok(Uint8Array::from(
        dsse::pae(payload_type, &payload).as_slice(),
    ))
}
