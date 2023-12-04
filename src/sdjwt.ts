import { SD_SEPARATOR } from './constant';
import { Disclosure } from './disclosure';
import { Jwt } from './jwt';
import { KBJwt, kbHeader, kbPayload } from './kbjwt';

export class SDJwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
> {
  public jwt: any;
  public disclosures: Array<any> = [];
  public keyBinding?: any;

  public static decodeSDJwt<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: string,
  ): {
    jwt: Jwt<Header, Payload>;
    disclosures: any;
    kbJwt?: KBJwt;
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
      ? KBJwt.fromEncode<KBHeader, KBPayload>(encodedKeyBindingJwt)
      : undefined;
    const disclosures = encodedDisclosures.map(Disclosure.fromEncode);

    return {
      jwt,
      disclosures,
      kbJwt,
    };
  }
}
