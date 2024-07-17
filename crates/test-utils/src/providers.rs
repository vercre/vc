pub mod client;
pub mod issuer;
pub mod proof;
pub mod server;
pub mod state;
pub mod subject;

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
pub const VERIFIER_ID: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
pub const VERIFIER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

#[derive(Default, Clone, Debug)]
pub struct Issuance {
    pub client: client::Store,
    pub issuer: issuer::Store,
    pub server: server::Store,
    pub subject: subject::Store,
    pub state: state::Store,
}

impl Issuance {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: client::Store::new(),
            issuer: issuer::Store::new(),
            server: server::Store::new(),
            subject: subject::Store::new(),
            state: state::Store::new(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Presentation {
    pub client: client::Store,
    pub state: state::Store,
}

impl Presentation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: client::Store::new(),
            state: state::Store::new(),
        }
    }
}
