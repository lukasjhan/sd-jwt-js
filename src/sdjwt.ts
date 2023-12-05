import { SD_SEPARATOR } from './constant';
import { Disclosure } from './disclosure';
import { SDJWTException } from './error';
import { Jwt } from './jwt';
import { KBJwt, kbHeader, kbPayload } from './kbjwt';

export type SDJwtData<
  Header extends Record<string, any>,
  Payload extends Record<string, any>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> = {
  jwt?: Jwt<Header, Payload>;
  disclosures?: Array<Disclosure<any>>;
  kbJwt?: KBJwt<KBHeader, KBPayload>;
};

export class SDJwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> {
  public jwt?: Jwt<Header, Payload>;
  public disclosures?: Array<Disclosure<any>>;
  public kbJwt?: KBJwt<KBHeader, KBPayload>;

  constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>) {
    this.jwt = data?.jwt;
    this.disclosures = data?.disclosures;
    this.kbJwt = data?.kbJwt;
  }

  public static decodeSDJwt<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: string,
  ): {
    jwt: Jwt<Header, Payload>;
    disclosures: Array<Disclosure<any>>;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  } {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
    const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt);

    if (encodedDisclosures.length === 0) {
      return {
        jwt,
        disclosures: [],
      };
    }

    const encodedKeyBindingJwt = encodedDisclosures.pop();
    const kbJwt = encodedKeyBindingJwt
      ? KBJwt.fromKBEncode<KBHeader, KBPayload>(encodedKeyBindingJwt)
      : undefined;
    const disclosures = encodedDisclosures.map(Disclosure.fromEncode);

    return {
      jwt,
      disclosures,
      kbJwt,
    };
  }

  public static fromEncode<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(encodedSdJwt: string): SDJwt<Header, Payload> {
    const { jwt, disclosures, kbJwt } = SDJwt.decodeSDJwt<
      Header,
      Payload,
      KBHeader,
      KBPayload
    >(encodedSdJwt);

    return new SDJwt<Header, Payload, KBHeader, KBPayload>({
      jwt,
      disclosures,
      kbJwt,
    });
  }

  public present() {}

  public verify() {}

  public encodeSDJwt() {
    const data: string[] = [];

    if (!this.jwt) {
      throw new SDJWTException('Invalid sd-jwt: jwt is missing');
    }

    const encodedJwt = this.jwt.encodeJwt();
    data.push(encodedJwt);

    if (this.disclosures && this.disclosures.length > 0) {
      const encodeddisclosures = this.disclosures
        .map((dc) => data.push(dc.encode()))
        .join(SD_SEPARATOR);
      data.push(encodeddisclosures);
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : '');
    return data.join(SD_SEPARATOR);
  }
}
