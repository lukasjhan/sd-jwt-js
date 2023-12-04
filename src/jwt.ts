import { Base64Url } from './base64url';
import { SDJWTException } from './error';
import { Signer, Verifier } from './type';

export function decodeJWT<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
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
  Header extends Record<string, any>,
  Payload extends Record<string, any>,
> = {
  header?: Header;
  payload?: Payload;
  signature?: Uint8Array;
};

export type JwtOptions = {
  signer?: Signer;
};

export class Jwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
> {
  public header?: Header;
  public payload?: Payload;
  public signature?: Uint8Array;

  public signer?: Signer;
  public verifier?: Verifier;

  constructor(data?: JwtData<Header, Payload>, options?: JwtOptions) {
    this.header = data?.header;
    this.payload = data?.payload;
    this.signature = data?.signature;
    this.signer = options?.signer;
  }

  public static fromCompact<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
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

  public setSigner(signer: Signer): Jwt<Header, Payload> {
    this.signer = signer;
    return this;
  }

  public setVerifier(verifier: Verifier): Jwt<Header, Payload> {
    this.verifier = verifier;
    return this;
  }

  public async sign() {
    if (!this.header || !this.payload || !this.signer) {
      throw new SDJWTException('Sign Error: Invalid JWT');
    }

    const header = Base64Url.encode(JSON.stringify(this.header));
    const payload = Base64Url.encode(JSON.stringify(this.payload));
    const data = `${header}.${payload}`;
    this.signature = await this.signer(data);

    return this.signature;
  }

  public serialize(): string {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Serialize Error: Invalid JWT');
    }

    const header = Base64Url.encode(JSON.stringify(this.header));
    const payload = Base64Url.encode(JSON.stringify(this.payload));
    const signature = Buffer.from(this.signature).toString('base64url');
    const compact = `${header}.${payload}.${signature}`;

    return compact;
  }

  public async verify() {
    if (!this.header || !this.payload || !this.signature || !this.verifier) {
      throw new SDJWTException('Verify Error: Invalid JWT');
    }

    const header = Base64Url.encode(JSON.stringify(this.header));
    const payload = Base64Url.encode(JSON.stringify(this.payload));
    const data = `${header}.${payload}`;

    return this.verifier(data, this.signature);
  }
}
