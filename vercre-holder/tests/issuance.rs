mod test_provider;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use issuer_provider::{CREDENTIAL_ISSUER, NORMAL_USER, CLIENT_ID};
use vercre_holder::callback::CredentialStorer;
use vercre_holder::issuance::{OfferRequest, PinRequest, Status};
use vercre_holder::Endpoint;
use vercre_issuer::create_offer::CreateOfferRequest;

static PROVIDER: LazyLock<test_provider::Provider> =
    LazyLock::new(|| test_provider::Provider::new());

fn sample_offer_request() -> CreateOfferRequest {
    CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        credential_configuration_ids: vec!["EmployeeID_JWT".into()],
        holder_id: Some(NORMAL_USER.into()),
        pre_authorize: true,
        tx_code_required: true,
        callback_id: Some("1234".into()),
    }
}

#[tokio::test]
async fn e2e_issuance() {
    // Use the issuance service endpoint to create a sample offer so we can get a valid
    // pre-auhorized code.
    let offer = vercre_issuer::Endpoint::new(PROVIDER.clone())
        .create_offer(&sample_offer_request())
        .await
        .expect("should get offer");

    // Initiate the pre-authorized code flow
    let offer_req = OfferRequest {
        client_id: CLIENT_ID.into(),
        offer: offer.credential_offer.expect("should have offer"),
    };
    let issuance =
        Endpoint::new(PROVIDER.clone()).offer(&offer_req).await.expect("should process offer");
    assert_snapshot!("issuance_created", issuance, {
        ".id" => "[id]",
        ".offer" => insta::sorted_redaction(),
        ".offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Accept offer
    let issuance = Endpoint::new(PROVIDER.clone())
        .accept(issuance.id.clone())
        .await
        .expect("should accept offer");
    assert_eq!(issuance.status, Status::PendingPin);
    assert_snapshot!("issuance_accepted", issuance, {
        ".id" => "[id]",
        ".offer" => insta::sorted_redaction(),
        ".offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Enter PIN
    let pin_req = PinRequest {
        id: issuance.id.clone(),
        pin: offer.user_code.expect("should have user code"),
    };
    let issuance = Endpoint::new(PROVIDER.clone()).pin(&pin_req).await.expect("should apply pin");
    assert_eq!(issuance.status, Status::Accepted);
    assert_eq!(issuance.pin, Some(pin_req.pin.clone()));
    assert_snapshot!("issuance_pin", issuance, {
        ".id" => "[id]",
        ".offer" => insta::sorted_redaction(),
        ".offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
        ".pin" => "[pin]",
    });

    // Get (and store) credentials
    Endpoint::new(PROVIDER.clone())
        .get_credentials(issuance.id.clone())
        .await
        .expect("should get credentials");
    let credentials = CredentialStorer::find(&PROVIDER.clone(), None)
        .await
        .expect("should retrieve all credentials");
    assert_eq!(credentials.len(), 1);
    assert_snapshot!("credentials", credentials, {
        "[0].vc.issuanceDate" => "[issuanceDate]",
        "[0].vc" => insta::sorted_redaction(),
        "[0].vc.credentialSubject" => insta::sorted_redaction(),
        "[0].metadata" => insta::sorted_redaction(),
        "[0].metadata.credential_definition" => insta::sorted_redaction(),
        "[0].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
        "[0].issued" => "[issued]",
    });
}
