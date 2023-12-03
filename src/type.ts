export type SDJWTCompact = string;

export type SDJWTConfig = {
  decoy?: number;
  omitTyp?: boolean;
  omitIat?: boolean;
  hasher?: (data: string) => string;
  saltGenerator?: (length: number) => string;
};

export type OrPromise<T> = T | Promise<T>;

export type Signer<
  Header extends Record<string, unknown> = Record<string, unknown>
> = (input: string, header: Header) => OrPromise<Uint8Array>;
