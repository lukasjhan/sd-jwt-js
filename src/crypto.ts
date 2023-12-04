import Crypto from 'node:crypto';
import { SDJWTException } from './error';
import { OrPromise, Signer, Verifier } from './type';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    throw new SDJWTException('Salt length must be greater than 0.');
  }
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const random = (min: number, max: number): number => {
  if (min > max) {
    throw new SDJWTException(
      'Invalid range. The minimum value must be less than or equal to the maximum value.',
    );
  }
  const range = max - min + 1;
  const randomBytes = Crypto.randomBytes(4);
  const randomValue = randomBytes.readUInt32BE(0);
  const scaledRandom = randomValue % range;
  return min + scaledRandom;
};

export const hash = (data: string): string => {
  const hash = Crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
};

const sign = (data: string, key: Crypto.KeyObject): OrPromise<Uint8Array> => {
  return Crypto.sign(null, Buffer.from(data), key);
};

const verify = (
  data: string,
  key: Crypto.KeyObject,
  sig: Uint8Array,
): OrPromise<boolean> => {
  return Crypto.verify(null, Buffer.from(data), key, sig);
};

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

export class DefaultSigner {
  public pubKey: Crypto.KeyObject;
  public privKey: Crypto.KeyObject;

  constructor(keyPair?: Crypto.KeyPairKeyObjectResult) {
    if (keyPair) {
      this.pubKey = keyPair.publicKey;
      this.privKey = keyPair.privateKey;
      return;
    }

    const { privateKey, publicKey } = createKeyPair();
    this.pubKey = publicKey;
    this.privKey = privateKey;
  }

  public getPublicKey(): string {
    return this.pubKey
      .export({
        type: 'spki',
        format: 'pem',
      })
      .toString('base64');
  }

  public getPrivateKey(): string {
    return this.privKey
      .export({
        type: 'pkcs8',
        format: 'pem',
      })
      .toString('base64');
  }

  public getSigner(): Signer {
    return this.sign.bind(this);
  }

  public getVerifier(): Verifier {
    return this.verify.bind(this);
  }

  async sign(data: string): Promise<Uint8Array> {
    return sign(data, this.privKey);
  }

  async verify(data: string, sig: Uint8Array): Promise<boolean> {
    return verify(data, this.pubKey, sig);
  }
}
