// Optional Node-only conformance backend. It is not imported by the portable SDK entrypoint.
import {
  createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, hkdfSync,
} from 'node:crypto';
import { bytes } from './portable-core.mjs';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const privateKey = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(raw)]), format: 'der', type: 'pkcs8' });
const publicKey = (raw) => createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });

/** Native Node implementation of the portable backend contract, used for byte conformance. */
export const NODE_CRYPTO_BACKEND = Object.freeze({
  getPublicKey(secret) { return new Uint8Array(createPublicKey(privateKey(secret)).export({ format: 'der', type: 'spki' }).subarray(-32)); },
  getSharedSecret(secret, peer) { return new Uint8Array(diffieHellman({ privateKey: privateKey(secret), publicKey: publicKey(peer) })); },
  hkdfSha256(shared, salt, info, length) { return new Uint8Array(hkdfSync('sha256', shared, salt, info, length)); },
  seal(key, nonce, aad, plaintext) {
    const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    return new Uint8Array(bytes(new Uint8Array(cipher.update(plaintext)), new Uint8Array(cipher.final()), new Uint8Array(cipher.getAuthTag())));
  },
  open(key, nonce, aad, sealed) {
    const ciphertext = sealed.subarray(0, -16); const tag = sealed.subarray(-16);
    const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length }); decipher.setAuthTag(tag);
    return new Uint8Array(bytes(new Uint8Array(decipher.update(ciphertext)), new Uint8Array(decipher.final())));
  },
});
