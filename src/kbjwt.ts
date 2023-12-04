import { SDJWTException } from './error';
import { Jwt } from './jwt';

export type kbHeader = { typ: string; alg: string };
export type kbPayload = {
  iat: string;
  aud: string;
  nonce: string;
  _sd_hash: string;
};

export class KBJwt<
  Header extends kbHeader = kbHeader,
  Payload extends kbPayload = kbPayload,
> extends Jwt<Header, Payload> {
  public async verify() {
    if (
      !this.header?.alg ||
      !this.header.typ ||
      !this.payload?.iat ||
      !this.payload?.aud ||
      !this.payload?.nonce ||
      !this.payload?._sd_hash
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt');
    }
    return await super.verify();
  }
}
