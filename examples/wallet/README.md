# Wallet Example

Tauri + React + Typescript

## Getting Started

Install dependencies:

```bash
pnpm install
```

Launch the Tauri app using:

```bash
pnpm tauri dev
```

OR use VS Code debugger with the `Tauri Bundle` launch configuration.

### Issuance

Launch the `examples/issuance` http server. It runs on port 8080 by default.

Once both the VCI server and Tauri app are running, the issuance process can be 
initiated by sending a Credential Offer to the wallet.

```bash
# get pre-authorized credential offer from issuance service
RESP=$(curl --json '{
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true
    }' \
    http://localhost:8080/create_offer)

# send credential offer to wallet (Tauri app)
OFFER=$(echo $RESP | jq '.credential_offer' | jq -r @uri)
open "openid-credential-offer://?credential_offer=$OFFER"
```

In order to access the credential, paste the `credential_offer` object response from the `issuer/create_offer` endpoint into the Offer input in the wallet UI
```json
{
    "credential_configuration_ids": [
        "EmployeeID_JWT"
    ],
    "credential_issuer": "http://localhost:8080", // example host 
    "grants": {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "<pre-authorized_code>",
            "tx_code": {
                "description": "Please provide the one-time code received",
                "input_mode": "numeric",
                "length": 6
            }
        }
    }
}
```

# print user pin
echo $RESP | jq '.user_code'

The resultant link should look like:

```bash
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credentials%22%3A%5B%22EmployeeID_JWT%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3Anull%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22authorization_server%22%3Anull%2C%22interval%22%3Anull%2C%22pre-authorized_code%22%3A%22QCZ1WTMmYjNDUjJSQHNTMmRAR3RaU1ZPSkAlaW1TQVo%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D
```

### Presentation

Launch the `examples/presentation` http server. It runs on port 8080 by default.

Once both the VP server and Tauri app are running, the presentation process can be initiated by sending a Presentation Request to the wallet.

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

# send presentation request to wallet (Tauri app)
REQUEST_URI=$(echo $RESP | jq '.request_uri' | jq -r @uri)
open "openid-vc://request_uri=$REQUEST_URI"
```

The resultant link should look like:

```bash
openid-vc://request_uri=http://localhost:8080/request/R1BjcyojV01ZVjhvY0shayV-c3QyNEV5b1U1S2Eobl4
```

## Troubleshooting

### Forms to bypass deep links

To bypass the deep links to initiate issuance or presentation, the user interface has forms that accept the JSON responses from the issuance and verification services. This is not the intended user experience but allows faster shell development and testing.

For issuance, run the issuance example service as above then

```bash
# get pre-authorized credential offer from issuance service
RESP=$(curl --json '{
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true
    }' \
    http://localhost:8080/create_offer)

# paste this JSON into the add-credential form in the Tauri app
echo $RESP | jq '.credential_offer'

# print user pin
echo $RESP | jq '.user_code'
```

For presentation, run the presentation example service as above then

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

# paste this JSON into the start presentation form in the Tauri app
echo $RESP | jq '.request_uri'
```

### Debuggable Release

To build a "debuggable" release:

```bash
cargo tauri build --debug
```

### MacOS Custom URL Scheme

Following iterations of development, the custom URL scheme may become registered multiple times, including to the wrong binary. Troubleshoot and clean up by using the following commands:

```bash
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"

# List schema bindings:
$LSREGISTER -dump URLSchemeBinding

# Clean up old entries:
$LSREGISTER -kill -r -domain local -domain system -domain user
```

To re-register the URL scheme, run the following from the `tauri` directory:

```bash
pnpm tauri build --debug
```

### Hanging Tauri Process

Periodically, the VS Code debugger will exit with an error and leave the Tauri process running. This prevents the app from being run again because the port is in use. To fix, kill the process by running:

```bash
lsof -nP -iTCP:1420 | grep LISTEN | awk '{print($2)}' | xargs -I '{}' kill {}
```

## Updating Dependencies

```bash
# Tauri
pnpm update

# Rust
cargo update
```

## Android 

In order to get it running on mobile you will need to configure your hosts file. <br />
Tauri has some instructions on how to get started [here]("https://v2.tauri.app/plugin/http-client/"). 

1. In order to get android studio and the emulator working on your machine, update your `zshrc` file configuration to look like this 
```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export NDK_VERSION=$(ls -1 $ANDROID_HOME/ndk | sort -V | tail -n 1)
export NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
export ANDROID_SDK_ROOT=$ANDROID_HOME

export PATH=$PATH:$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Java configuration
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export PATH=$JAVA_HOME/bin:$PATH
```
2. Run `pnpm tauri android init` to generate the application
3. Then run `pnpm tauri android dev` to build and run it. 