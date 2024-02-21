import { SDJwtInstance } from '@hopae/sd-jwt-core';

export class SdJwtVcInstance extends SDJwtInstance {
  /**
   *
   * Verify the SD JWT VC
   *
   * It validates
   */
  public async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    requireKeyBindings?: boolean,
  ) {
    return super.verify(encodedSDJwt, requiredClaimKeys, requireKeyBindings);
  }
}
