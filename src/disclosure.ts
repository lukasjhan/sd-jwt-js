import { Base64Url } from './base64url';
import { SDJWTException } from './error';

export type DisclosureData = [string, string, unknown] | [string, unknown];

export class Disclosure {
  private salt: string;
  private key?: string;
  private value: unknown;
  private _digest: string | undefined;

  public constructor(data: DisclosureData) {
    if (data.length === 2) {
      this.salt = data[0];
      this.value = data[1];
      return;
    }
    if (data.length === 3) {
      this.salt = data[0];
      this.key = data[1] as string;
      this.value = data[2];
      return;
    }
    throw new SDJWTException('Invalid disclosure data');
  }

  public static fromEncode(s: string) {
    const item = JSON.parse(Base64Url.decode(s)) as DisclosureData;
    return Disclosure.fromArray(item);
  }

  public static fromArray(item: DisclosureData) {
    return new Disclosure(item);
  }

  public get encoded() {
    return Base64url.encodeFromJson(this.decoded);
  }

  public get decoded(): DisclosureItem {
    return this.key
      ? [this.salt, this.key, this.value]
      : [this.salt, this.value];
  }

  public async digest(hasher: Hasher) {
    // Memoize value so we don't have to re-compute
    if (!this._digest) {
      const hash = await hasher(this.encoded);
      this._digest = Base64url.encode(hash);
    }

    return this._digest;
  }

  public toString() {
    return this.encoded;
  }
}
