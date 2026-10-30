//! The serialized refusal contract keeps the native discriminant and fields.

use dsse::Error;
use serde_json::json;

#[test]
fn unit_tuple_and_struct_refusals_keep_their_native_shapes() -> Result<(), serde_json::Error> {
    assert_eq!(
        serde_json::to_value(Error::ZeroThreshold)?,
        json!({"variant": "ZeroThreshold"})
    );
    assert_eq!(
        serde_json::to_value(Error::InvalidKey("wrong length".to_owned()))?,
        json!({"variant": "InvalidKey", "fields": "wrong length"})
    );
    assert_eq!(
        serde_json::to_value(Error::ThresholdNotMet {
            accepted: 1,
            threshold: 2
        })?,
        json!({"variant": "ThresholdNotMet", "fields": {"accepted": 1, "threshold": 2}})
    );
    Ok(())
}
