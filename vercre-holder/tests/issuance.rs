mod providers;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_holder::provider::CredentialStorer;
use vercre_holder::{OfferRequest, PinRequest, Status};
use vercre_issuer::{CreateOfferRequest, CredentialOfferType};

use crate::providers::holder;

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(Some(ISSUER_PROVIDER.clone()), None));

static OFFER_REQUEST: LazyLock<CreateOfferRequest> = LazyLock::new(|| CreateOfferRequest {
    credential_issuer: CREDENTIAL_ISSUER.into(),
    credential_configuration_ids: vec!["EmployeeID_JWT".into()],
    subject_id: Some(NORMAL_USER.into()),
    pre_authorize: true,
    tx_code_required: true,
    callback_id: Some("1234".into()),
});

#[tokio::test]
async fn e2e_issuance() {
    // Use the issuance service endpoint to create a sample offer so we can get a valid
    // pre-auhorized code.
    let offer_resp = vercre_issuer::create_offer(ISSUER_PROVIDER.clone(), &OFFER_REQUEST)
        .await
        .expect("should get offer");

    let CredentialOfferType::Object(offer) = offer_resp.credential_offer else {
        panic!("expected CredentialOfferType::Object");
    };

    // Initiate the pre-authorized code flow
    let offer_req = OfferRequest {
        client_id: CLIENT_ID.into(),
        offer,
    };
    let issuance = vercre_holder::offer(HOLDER_PROVIDER.clone(), &offer_req)
        .await
        .expect("should process offer");

    assert_snapshot!("issuance_created", issuance, {
        ".id" => "[id]",
        ".offer" => insta::sorted_redaction(),
        ".offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Accept offer
    let issuance = vercre_holder::accept(HOLDER_PROVIDER.clone(), issuance.id.clone())
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
        pin: offer_resp.user_code.expect("should have user code"),
    };
    let issuance =
        vercre_holder::pin(HOLDER_PROVIDER.clone(), &pin_req).await.expect("should apply pin");

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
    vercre_holder::get_credentials(HOLDER_PROVIDER.clone(), issuance.id.clone())
        .await
        .expect("should get credentials");

    let credentials = CredentialStorer::find(&HOLDER_PROVIDER.clone(), None)
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
