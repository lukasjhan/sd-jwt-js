import { generateSalt, hash } from './crypto';
import { SDJwt } from './sdjwt';
import { DisclosureFrame, SDJWTConfig } from './type';

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

  public async issue<Header extends Record<string, any>, Payload>(
    payload: Payload,
    disclosureFrame?: DisclosureFrame,
    options?: any,
  ): Promise<SDJwt<Header, Payload>> {}

  public async present(
    encodedSDJwt: string,
    presentationFrame?: any,
    options?: any,
  ): Promise<string> {}

  public async verify(
    encodedSDJwt: string,
    claims?: any,
    options?: any,
  ): Promise<boolean> {}

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
