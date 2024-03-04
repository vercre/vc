use anyhow::Result;
use assert_let_bind::assert_let;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use lazy_static::lazy_static;
use serde_json::json;
use test_utils::vci_provider::{Provider, ISSUER, PENDING_USER};
use test_utils::wallet;
use vercre_vci::credential::{CredentialRequest, CredentialResponse};
use vercre_vci::deferred::{DeferredCredentialRequest, DeferredCredentialResponse};
use vercre_vci::invoke::{InvokeRequest, InvokeResponse};
use vercre_vci::jwt::{self, Jwt};
use vercre_vci::token::{TokenRequest, TokenResponse};
use vercre_vci::{Endpoint, ProofClaims};

lazy_static! {
    static ref PROVIDER: Provider = Provider::new();
}

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn deferred_flow() {
    test_utils::init_tracer();

    // go through the pre-auth flow to token endpoint
    let token_resp = get_offer().and_then(get_token).await.expect("Ok");
    let credential_resp = get_credential(token_resp.clone()).await.expect("Ok");

    assert_snapshot!("credential-response", &credential_resp, {
        ".transaction_id" => "[transaction_id]",
        ".c_nonce" => "[c_nonce]",
        ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    });

    let deferred_resp = get_deferred(token_resp, credential_resp.clone()).await.expect("Ok");

    assert_snapshot!("deferred-response", deferred_resp, {
        ".credential" => "[credential]",
        ".c_nonce" => "[c_nonce]",
        ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    });
}

// Simulate Issuer request to '/invoke' endpoint to get credential offer to use to
// make credential offer to Wallet.
async fn get_offer() -> Result<InvokeResponse> {
    // offer request
    let body = json!({
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "holder_id": PENDING_USER,
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    });

    let mut request = serde_json::from_value::<InvokeRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.invoke(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: InvokeResponse) -> Result<TokenResponse> {
    assert_let!(Some(offer), &input.credential_offer);
    assert_let!(Some(grants), &offer.grants);
    assert_let!(Some(pre_authorized_code), &grants.pre_authorized_code);

    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": wallet::did(),
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
        "user_code": input.user_code.unwrap_or_default(),
    });

    let mut request = serde_json::from_value::<TokenRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.token(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    // create CredentialRequest to 'send' to the app
    let jwt_enc = Jwt {
        header: jwt::Header {
            typ: String::from("vercre-vci-proof+jwt"),
            alg: wallet::alg(),
            kid: wallet::kid(),
        },
        claims: ProofClaims {
            iss: wallet::did(),
            aud: ISSUER.to_string(),
            iat: Utc::now().timestamp(),
            nonce: input.c_nonce.unwrap_or_default(),
        },
    }
    .to_string();
    let sig = wallet::sign(jwt_enc.as_bytes());
    let sig_enc = Base64UrlUnpadded::encode_string(&sig);
    let signed_jwt = format!("{jwt_enc}.{sig_enc}");
    let body = json!({
        "format": "jwt_vc_json",
        "credential_definition": {
            "type": [
                "VerifiableCredential",
                "EmployeeIDCredential"
            ]
        },
        "proof":{
            "proof_type": "jwt",
            "jwt": signed_jwt
        }
    });

    let mut request = serde_json::from_value::<CredentialRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();
    request.access_token = input.access_token;

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.credential(&request).await?;
    Ok(response)
}

async fn get_deferred(
    tkn: TokenResponse, cred_resp: CredentialResponse,
) -> Result<DeferredCredentialResponse> {
    let request = DeferredCredentialRequest {
        credential_issuer: ISSUER.to_string(),
        access_token: tkn.access_token,
        transaction_id: cred_resp.transaction_id.expect("should have transaction_id"),
    };

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.deferred(&request).await?;
    Ok(response)
}
