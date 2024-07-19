use openid::issuer::CredentialConfiguration;

pub fn credential_configuration() -> CredentialConfiguration {
    let issuer = crate::store::issuer::Store::new()
        .get("http://vercre.io".into())
        .expect("should get issuer");

    issuer
        .credential_configurations_supported
        .get("EmployeeID_JWT".into())
        .expect("should exist")
        .clone()
}
