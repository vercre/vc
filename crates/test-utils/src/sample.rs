use openid::issuer::CredentialConfiguration;

pub fn credential_configuration() -> CredentialConfiguration {
    let issuer =
        crate::store::issuer::Store::new().get("http://vercre.io").expect("should get issuer");

    issuer.credential_configurations_supported.get("EmployeeID_JWT").expect("should exist").clone()
}
