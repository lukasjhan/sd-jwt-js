import { KeyObject } from 'crypto';
import { createKeyPair, generateSalt, hash } from './crypto';
import { Jwt } from './jwt';
import { SDJwt, pack } from './sdjwt';
import {
  DisclosureFrame,
  PresentationFrame,
  SDJWTConfig,
  SD_JWT_TYP,
} from './type';

export const defaultConfig: Required<SDJWTConfig> = {
  omitDecoy: false,
  omitTyp: false,
  hasher: hash,
  saltGenerator: generateSalt,
};

export class SDJwtInstance {
  private userConfig: SDJWTConfig = {};
  private publicKey: KeyObject;
  private privateKey: KeyObject;

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
    const { privateKey, publicKey } = createKeyPair();
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public create(userConfig?: SDJWTConfig): SDJwtInstance {
    return new SDJwtInstance(userConfig);
  }

  public async issue<Payload extends object>(
    payload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      sign_alg?: string;
      hash_alg?: string;
    },
  ): Promise<string> {
    const { packedClaims, disclosures } = pack(payload, disclosureFrame);
    const jwt = new Jwt({
      header: { alg: options?.sign_alg ?? 'EdDSA', typ: SD_JWT_TYP },
      payload: {
        ...packedClaims,
        _sd_alg: options?.hash_alg ?? 'sha-256',
      },
    });
    await jwt.sign(this.privateKey);

    const sdJwt = new SDJwt({
      jwt,
      disclosures,
    });

    return sdJwt.encodeSDJwt();
  }

  public async present<T>(
    encodedSDJwt: string,
    presentationFrame?: PresentationFrame<T>,
    options?: any,
  ): Promise<string> {
    return '';
  }

  public async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    options?: any,
  ): Promise<boolean> {
    return false;
  }

  public async validate(encodedSDJwt: string): Promise<boolean> {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      return false;
    }

    const verified = await sdjwt.jwt.verify(this.publicKey);
    return verified;
  }

  public config(newConfig: SDJWTConfig) {
    this.userConfig = { ...this.userConfig, ...newConfig };
  }

  public encode(sdJwt: SDJwt) {
    return sdJwt.encodeSDJwt();
  }

  public decode(endcodedSDJwt: string) {
    return SDJwt.fromEncode(endcodedSDJwt);
  }
}

const defaultInstance = new SDJwtInstance();
export default defaultInstance;
