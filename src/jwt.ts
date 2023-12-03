import { Base64Url } from './base64url';
import { sign as defaultSigner } from './crypto';
import { SDJWTException } from './error';
import { Signer } from './type';

export function decodeJWT<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>
>(input: string): { header: Header; payload: Payload; signature: Uint8Array } {
  const { 0: header, 1: payload, 2: signature, length } = input.split('.');
  if (length !== 3) {
    throw new SDJWTException('Invalid JWT as input');
  }

  return {
    header: JSON.parse(Base64Url.decode(header)),
    payload: JSON.parse(Base64Url.decode(payload)),
    signature: Uint8Array.from(Buffer.from(signature, 'base64url')),
  };
}

export type JwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>
> = {
  header?: Header;
  payload?: Payload;
  signature?: Uint8Array;
};

export type JwtOptions<
  Header extends Record<string, unknown> = Record<string, unknown>
> = {
  signer?: Signer<Header>;
};

export class Jwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>
> {
  public header?: Header;
  public payload?: Payload;
  public signature?: Uint8Array;

  public signer?: Signer<Header>;

  constructor(data?: JwtData<Header, Payload>, options?: JwtOptions<Header>) {
    this.header = data?.header;
    this.payload = data?.payload;
    this.signature = data?.signature;
    this.signer = options?.signer;
  }

  public static fromCompact<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>
  >(compact: string): Jwt<Header, Payload> {
    const { header, payload, signature } = decodeJWT<Header, Payload>(compact);

    const jwt = new Jwt<Header, Payload>({
      header,
      payload,
      signature,
    });

    return jwt;
  }

  public setHeader(header: Header): Jwt<Header, Payload> {
    this.header = header;
    return this;
  }

  public setPayload(payload: Payload): Jwt<Header, Payload> {
    this.payload = payload;
    return this;
  }

  public setSigner(signer: Signer<Header>): Jwt<Header, Payload> {
    this.signer = signer;
    return this;
  }

  public defaultSigner: Signer<Header> = (input: string, header: Header) => {
    this.setHeader({ alg: 'EdDSA' });
    return defaultSigner(input);
  };

  public async sign() {}
}
