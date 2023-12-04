import Crypto from 'node:crypto';

export type SDJWTCompact = string;

export type SDJWTConfig = {
  decoy?: number;
  omitTyp?: boolean;
  omitIat?: boolean;
  hasher?: (data: string) => string;
  saltGenerator?: (length: number) => string;
};

export type OrPromise<T> = T | Promise<T>;

export type Signer = (data: string) => OrPromise<Uint8Array>;
export type Verifier = (data: string, sig: Uint8Array) => OrPromise<boolean>;
export type Hasher = (data: string) => string;
