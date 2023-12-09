import { DefaultSigner, generateSalt, hash } from './crypto';
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

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  public create(userConfig?: SDJWTConfig): SDJwtInstance {
    return new SDJwtInstance(userConfig);
  }

  public async issue<
    Header extends Record<string, any>,
    Payload extends object,
  >(
    payload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      header?: Header;
    },
  ): Promise<string> {
    const defaultSigner = new DefaultSigner();
    const { packedClaims, disclosures } = pack(payload, disclosureFrame);
    const jwt = new Jwt({
      header: { alg: 'EdDSA', ...options?.header, typ: SD_JWT_TYP },
      payload: {
        ...packedClaims,
        _sd_alg: 'sha-256',
      },
    });
    jwt.setSigner(defaultSigner.getSigner());
    await jwt.sign();

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
    return false;
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
