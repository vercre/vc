
mod create_offer;

/// Construct a `serde_json::Value` from a JSON literal.
///
/// ```
/// # use serde_json::json;
/// #
/// let value = json!({
///     "code": 200,
///     "success": true,
///     "payload": {
///         "features": [
///             "serde",
///             "json"
///         ],
///         "homepage": null
///     }
/// });
/// ```
///
/// Variables or expressions can be interpolated into the JSON literal. Any type
/// interpolated into an array element or object value must implement Serde's
/// `Serialize` trait, while any type interpolated into a object key must
/// implement `Into<String>`. If the `Serialize` implementation of the
/// interpolated type decides to fail, or if the interpolated type contains a
/// map with non-string keys, the `json!` macro will panic.
///
/// ```
/// # use serde_json::json;
/// #
/// let code = 200;
/// let features = vec!["serde", "json"];
///
/// let value = json!({
///     "code": code,
///     "success": code == 200,
///     "payload": {
///         features[0]: features[1]
///     }
/// });
/// ```
///
/// Trailing commas are allowed inside both arrays and objects.
///
/// ```
/// # use serde_json::json;
/// #
/// let value = json!(["notice", "the", "trailing", "comma -->",]);
/// ```
#[macro_export]
macro_rules! create_offer_request {
    ({ $($json:tt)+ }) => {{
        let mut offer = $crate::issuer::CreateOfferRequest::default(); //serde_json::Map::new();
        $crate::internal_create_offer!(@object offer () ($($json)+) ($($json)+));
        offer
    }};
}

#[cfg(test)]
mod tests {
    use crate::issuer::SendType;

    const CREDENTIAL_ISSUER: &str = "http://vercre.io";

    #[test]
    fn create_offer() {
        let x = create_offer_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "credential_configuration_ids":["EmployeeID_JWT"],
            "subject_id": "normal_user",
            "pre-authorize": true,
            "tx_code_required": false,
            "send_type": SendType::ByRef,
            // "object": {
            //     "key": "value"
            // }
        });

        println!("{:?}", x);
    }
}