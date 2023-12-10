import { generateSalt, hash } from './crypto';
import { Jwt } from './jwt';
import { SDJwt, pack } from './sdjwt';
import { DisclosureFrame, SDJWTConfig, SD_JWT_TYP } from './type';
import { KeyLike } from 'jose';

export const defaultConfig: Required<SDJWTConfig> = {
  omitDecoy: false,
  omitTyp: false,
  hasher: hash,
  saltGenerator: generateSalt,
};

export class SDJwtInstance {
  public static DEFAULT_ALG = 'EdDSA';
  public static DEFAULT_HASH_ALG = 'sha-256';

  private userConfig: SDJWTConfig = {};

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  public create(userConfig?: SDJWTConfig): SDJwtInstance {
    return new SDJwtInstance(userConfig);
  }

  public async issue<Payload extends object>(
    payload: Payload,
    privateKey: Uint8Array | KeyLike,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      sign_alg?: string;
      hash_alg?: string;
    },
  ): Promise<string> {
    const { packedClaims, disclosures } = pack(payload, disclosureFrame);
    const alg = options?.sign_alg ?? SDJwtInstance.DEFAULT_ALG;
    const header = this.userConfig.omitTyp ? { alg } : { alg, typ: SD_JWT_TYP };
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: options?.hash_alg ?? SDJwtInstance.DEFAULT_HASH_ALG,
      },
    });
    await jwt.sign(privateKey);

    const sdJwt = new SDJwt({
      jwt,
      disclosures,
    });

    return sdJwt.encodeSDJwt();
  }

  public present<T>(encodedSDJwt: string, presentationKeys?: string[]): string {
    if (!presentationKeys) return encodedSDJwt;
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    return sdjwt.present(presentationKeys);
  }

  public async verify(
    encodedSDJwt: string,
    publicKey: Uint8Array | KeyLike,
    requiredClaimKeys?: string[],
    options?: any,
  ): Promise<boolean> {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      return false;
    }
    const validated = this.validate(encodedSDJwt, publicKey);
    if (!validated) {
      return false;
    }

    if (requiredClaimKeys) {
      const keys = sdjwt.keys();
      const missingKeys = requiredClaimKeys.filter((k) => !keys.includes(k));
      if (missingKeys.length > 0) {
        return false;
      }
    }

    return true;
  }

  public async validate(
    encodedSDJwt: string,
    publicKey: Uint8Array | KeyLike,
  ): Promise<boolean> {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      return false;
    }

    const verified = await sdjwt.jwt.verify(publicKey);
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

  public keys(endcodedSDJwt: string) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.keys();
  }

  public presentableKeys(endcodedSDJwt: string) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.presentableKeys();
  }
}

const defaultInstance = new SDJwtInstance();
export default defaultInstance;
