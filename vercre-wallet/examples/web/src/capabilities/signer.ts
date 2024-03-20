// IMPORTANT! This example is for demonstration purposes only. A real signer will need to be backed
// by a secure key store.

import * as ed from '@noble/ed25519';
import { encode } from 'punycode';
import * as st from 'shared_types/types/shared_types';

// Should be a key from a secure key store
const privateKey = new TextEncoder().encode('kKpNNWIPPK8hvgsuz6olBOXQ3xmumLU7');

export const signer = async (request: st.SignerRequest): Promise<st.SignerResponse> => {
    console.log('signer', request);

    switch (request.constructor) {
        case st.SignerRequestVariantSign: {
            const signRequest = request as st.SignerRequestVariantSign;
            const msg = Uint8Array.from(signRequest.value);
            const signed = await ed.signAsync(msg, privateKey);
            return new st.SignerResponseVariantSignature(Array.from(signed));
        }
        case st.SignerRequestVariantVerification: {
            const publicKey = await ed.getPublicKeyAsync(privateKey);
            const encoded = encodeURIComponent(new TextDecoder().decode(publicKey));

            const jwkStr = JSON.stringify({
                kty: 'OKP',
                crv: 'X25519',
                use: 'enc',
                x: encoded,
            });
            const jwkB64 = encodeURIComponent(jwkStr)
            const kid = `did:jwk:${jwkB64}#0`;

            return new st.SignerResponseVariantVerification('ed25519', kid);
        }
        default: {
            return new st.SignerResponseVariantErr('invalid request');
        }
    }
};
