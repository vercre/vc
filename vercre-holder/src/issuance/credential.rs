/// Take an issuance flow that has been accepted, get an access token, then use that to get
/// credentials.
pub(crate) async fn get_credentials<P>(provider: &P, current_state: &Issuance) -> Result<Issuance>
    where
    P: CredentialStorer + IssuerClient + Signer + Debug,
{
    let mut issuance = current_state.clone();
    issuance.status = Status::Accepted;
   
    // Request an access token from the issuer.
    let token_request = token_request(&issuance);
    issuance.token = provider.get_token(&issuance.id, &token_request).await?;

    // Request each credential offered.
    // TODO: concurrent requests. Possible if wallet is WASM?
    for (id, cfg) in &issuance.offered {
        // Construct a proof to be used in credential requests.
        let claims = ProofClaims {
            iss: Some(issuance.client_id.clone()),
            aud: issuance.offer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: issuance.token.c_nonce.clone(),
        };

        let jwt = jwt::encode(jwt::Payload::Proof, &claims, provider.clone()).await?;

        let proof = Proof {
            proof_type: "jwt".into(),
            jwt: Some(jwt),
            cwt: None,
        };

        let request = credential_request(&issuance, id, cfg, &proof);
        issuance.status = Status::Requested;
        let cred_res = provider.get_credential(&issuance.id, &request).await?;
        if cred_res.c_nonce.is_some() {
            issuance.token.c_nonce.clone_from(&cred_res.c_nonce);
        }
        if cred_res.c_nonce_expires_in.is_some() {
            issuance.token.c_nonce_expires_in.clone_from(&cred_res.c_nonce_expires_in);
        }

        // Create a credential in a useful wallet format.
        let mut credential = credential(&issuance, cfg, &cred_res).await?;
        
        // Base64-encoded logo if possible.
        if let Some(display) = &cfg.display {
            // TODO: Locale?
            if let Some(logo_info) = &display[0].logo {
                if let Some(uri) = &logo_info.uri {
                    if let Ok(logo) = provider.get_logo(&issuance.id, uri).await {
                        credential.logo = Some(logo);
                    }
                }
            }
        }
        provider.save(&credential).await?;
    }

    Ok(issuance)
}
