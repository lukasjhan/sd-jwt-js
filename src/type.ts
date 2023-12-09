import { Jwt } from './jwt';

export type SDJWTCompact = string;

export type SDJWTConfig = {
  omitDecoy?: boolean;
  omitTyp?: boolean;
  hasher?: (data: string) => string;
  saltGenerator?: (length: number) => string;
};

export type kbHeader = { typ: string; alg: string };
export type kbPayload = {
  iat: string;
  aud: string;
  nonce: string;
  _sd_hash: string;
};

export type KeyBinding = Jwt<kbHeader, kbPayload>;

export type OrPromise<T> = T | Promise<T>;

export type Signer = (data: string) => OrPromise<Uint8Array>;
export type Verifier = (data: string, sig: Uint8Array) => OrPromise<boolean>;
export type Hasher = (data: string) => string;
export type SaltGenerator = (length: number) => string;

type NonNever<T> = {
  [P in keyof T as T[P] extends never ? never : P]: T[P];
};

type SD<Payload> = { _sd?: Array<keyof Payload> };

type BaseFrame<Payload> = Payload extends Array<infer U>
  ? U extends object
    ? Record<number, BaseFrame<U>> & SD<Payload>
    : SD<Payload>
  : Payload extends Record<string, unknown>
  ? NonNever<
      {
        [K in keyof Payload]: Payload[K] extends object
          ? BaseFrame<Payload[K]>
          : never;
      } & SD<Payload>
    >
  : SD<Payload>;

export type Frame<T> = BaseFrame<T>;
export type DisclosureFrame<T> = Frame<T>;
export type PresentationFrame<T> = DisclosureFrame<T>;
