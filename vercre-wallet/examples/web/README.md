# Vercre Example Web Wallet

This is an example of a React (+Vite +TypeScript) shell for the Vercre wallet. It is a static,
single-page application with client-side rendering and uses a [Rust Crux](https://github.com/redbadger/crux) core that is transpiled to TypeScript.

## Getting Started

Generate the types by building the `types` crate:

```bash
cd types
cargo build
```

Install the TypeScript dependencies:

```bash
pnpm install
```

Run the app:

```bash
pnpm dev
```

Navigate to [https://localhost:3000](https://localhost:3000) in your browser.

## Issuing a Sample Credential

Launch the `vercre-vci/examples/http` server. It runs on port 8080 by default.

```bash
cd vercre-vci
cargo run --example http-issuer
```

Once both the VCI server and web app are running, the issuance process can be initiated by sending a Credential Offer to the wallet using curl commands to the example VCI server.



```bash
# get pre-authorized credential offer from issuance service
RESP=$(curl --json '{
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "holder_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    }' \
    http://localhost:8080/create_offer)



# This should open the web app in your browser and start the issuance process
OFFER=$(echo $RESP | jq '.credential_offer' | jq -r @uri)
open "https://localhost:3000/credential_offer?credential_offer=$OFFER"

# print user pin
echo $RESP | jq '.user_code'
```

You can also use the Add Credential form in the web app to paste the JSON response from the VCI server.

```bash
# paste this JSON into the add-credential form in the web app
echo $RESP | jq '.credential_offer'
```

## Verifying a Sample Credential

Launch the `vercre-vp/examples/http` server. It runs on port 8080 by default.

```bash
cd vercre-vp
cargo run --example http-verifier
```

Once both the VP server and web app are running, the verification process can be initiated by sending a Presentation Request to the wallet using curl commands to the example VP server.

```bash
# get presentation request from verification service
RESP=$(curl --json '{
        "purpose": "To verify employment",
        "input_descriptors": [{
            "id": "employment",
            "constraints": {
                "fields": [{
                    "path":["$.type"],
                    "filter": {
                        "type": "string",
                        "const": "EmployeeIDCredential"
                    }
                }]
            }
        }],
        "device_flow": "CrossDevice"
    }' \
    http://localhost:8080/create_request)

# This should open the web app in your browser and start the verification process
REQUEST_URI=$(echo $RESP | jq '.request_uri' | jq -r @uri)
open "https://localhost:3000/request_uri?request_uri=$REQUEST_URI"
```

You can also use the Present Credential form in the web app to paste the request URI from the VP server.
