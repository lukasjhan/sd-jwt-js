export const createHashMapping = (
  disclosures: Disclosure[],
  hasher: Hasher,
): SdDigestHashmap => {
  const map = {};
  disclosures.forEach((d) => {
    const digest = hasher(d.disclosure);
    map[digest] = d;
  });
  return map;
};

/**
 * Iterates through an array
 * inserts claim if disclosed
 * removes any undisclosed claims
 */
export const unpackArray = ({ arr, map }) => {
  const unpackedArray: any[] = [];
  arr.forEach((item) => {
    if (item instanceof Object) {
      // if Array item is { '...': <SD_HASH_DIGEST> }
      if (item[SD_LIST_PREFIX]) {
        const hash = item[SD_LIST_PREFIX];
        const disclosed = map[hash];
        if (disclosed) {
          unpackedArray.push(unpack({ obj: disclosed.value, map }));
        }
      } else {
        // unpack recursively
        unpackedArray.push(unpack({ obj: item, map }));
      }
    } else {
      unpackedArray.push(item);
    }
  });
  return unpackedArray;
};

/**
 * Iterates through an object
 * recursively unpack any child object or array
 * inserts claims if disclosed
 * removes any undisclosed claims
 */
export const unpack = ({ obj, map }) => {
  if (obj instanceof Object) {
    if (obj instanceof Array) {
      return unpackArray({ arr: obj, map });
    }

    for (const key in obj) {
      // if obj property value is an object
      // recursively unpack
      if (
        key !== SD_DIGEST &&
        key !== SD_LIST_PREFIX &&
        obj[key] instanceof Object
      ) {
        obj[key] = unpack({ obj: obj[key], map });
      }
    }

    const { _sd, ...payload } = obj;
    const claims = {};
    if (_sd) {
      _sd.forEach((hash) => {
        const disclosed = map[hash];
        if (disclosed) {
          claims[disclosed.key] = unpack({ obj: disclosed.value, map });
        }
      });
    }

    return Object.assign(payload, claims);
  }
  return obj;
};

/**
 * Helpers for packSDJWT
 */

export const createDisclosure = (
  claim: DisclosureClaim,
  hasher: Hasher,
  options?: {
    generateSalt?: SaltGenerator;
  },
): {
  hash: string;
  disclosure: string;
} => {
  let disclosureArray;
  const saltGenerator = options?.generateSalt
    ? options.generateSalt
    : generateSalt;
  const salt = saltGenerator(16);
  if (claim.key) {
    disclosureArray = [salt, claim.key, claim.value];
  } else {
    disclosureArray = [salt, claim.value];
  }

  const disclosure = base64encode(JSON.stringify(disclosureArray));
  const hash = hasher(disclosure);
  return {
    hash,
    disclosure,
  };
};

/**
 * Helpers for createSDMap
 */
const getParentSD = (
  disclosure: string,
  hasher: Hasher,
  hashmap: Record<string, string>,
): string[] => {
  const hash = hasher(disclosure);
  const parent = hashmap[hash];

  if (!parent) {
    return [];
  }

  if (hashmap[parent]) {
    return [parent].concat(getParentSD(parent, hasher, hashmap));
  }

  return [parent];
};

export const createDisclosureMap = (
  disclosures: Disclosure[],
  hasher: Hasher,
): DisclosureMap => {
  const map: DisclosureMap = {};
  const parentMap: Record<string, string> = {};

  disclosures.forEach(({ disclosure, value }) => {
    if (value && value._sd) {
      value._sd.forEach((sd: string) => {
        parentMap[sd] = disclosure;
      });
    }
  });

  disclosures.forEach(({ disclosure, value }) => {
    const parent = getParentSD(disclosure, hasher, parentMap);
    const hash = hasher(disclosure);

    map[hash] = {
      disclosure,
      value,
      parentDisclosures: parent,
    };
  });

  return map;
};
export const unpackArrayClaims = (arr: Array<any>, map: SdDigestHashmap) => {
  const unpackedArray: any[] = [];

  arr.forEach((item) => {
    if (item instanceof Object) {
      // if Array item is { '...': <SD_HASH_DIGEST> }
      if (item[SD_LIST_PREFIX]) {
        const hash = item[SD_LIST_PREFIX];
        const disclosed = map[hash];

        if (disclosed) {
          unpackedArray.push({
            '...': unpackClaims(disclosed.value, map),
            _sd: hash,
          });
        }
      } else {
        // unpack recursively
        const claims = unpackClaims(item, map);
        if (Object.keys(claims).length > 0) {
          unpackedArray.push(claims);
        } else {
          unpackedArray.push(null);
        }
      }
    } else {
      unpackedArray.push(null);
    }
  });

  return unpackedArray;
};

export const unpackClaims = (obj: any, map: SdDigestHashmap) => {
  if (obj instanceof Array) {
    return unpackArrayClaims(obj, map);
  }

  if (!isObject(obj)) {
    return {};
  }

  const claims = {};
  for (const key in obj) {
    // if obj property value is an object or array
    // recursively unpack
    if (
      key !== SD_DIGEST &&
      key !== SD_LIST_PREFIX &&
      obj[key] instanceof Object
    ) {
      const claim = unpackClaims(obj[key], map);
      if (Object.keys(claim).length > 0) {
        claims[key] = claim;
      }
    }
  }

  if (obj._sd) {
    obj._sd.forEach((hash: string) => {
      const disclosed = map[hash];
      if (disclosed) {
        claims[disclosed.key] = { _sd: hash };
      }
    });
  }

  return claims;
};

/**
 * Replaces _sd digests present in the SD-JWT with disclosed claims
 *
 * @param sdJWT SD-JWT
 * @param disclosures Array of Disclosure
 * @returns sd-jwt with all disclosed claims
 */
export const unpackSDJWT: UnpackSDJWT = async (
  sdjwt,
  disclosures,
  getHasher,
) => {
  const hashAlg = (sdjwt[SD_HASH_ALG] as string) || DEFAULT_SD_HASH_ALG;
  const hasher = await getHasher(hashAlg);
  const map = createHashMapping(disclosures, hasher);

  const { _sd_alg, ...payload } = sdjwt;
  return unpack({ obj: payload, map });
};

/**
 * Creates a SD-JWT from claims and disclosureFrame definition
 *
 * @param claims
 * @param disclosureFrame declares which properties to be selectively disclosable
 * @param hasher
 * @returns
 */
export const packSDJWT: PackSDJWT = async (
  claims,
  disclosureFrame,
  hasher,
  options,
) => {
  if (!isObject(disclosureFrame)) {
    throw new PackSDJWTError('DisclosureFrame must be an object');
  }

  if (!disclosureFrame) {
    throw new PackSDJWTError('no disclosureFrame found');
  }

  if (!hasher || typeof hasher !== 'function') {
    throw new PackSDJWTError('Hasher is required and must be a function');
  }

  if (!claims || typeof claims !== 'object') {
    throw new PackSDJWTError('no claims found');
  }

  const sd = disclosureFrame[SD_DIGEST];

  let packedClaims;
  let disclosures: any[] = [];

  if (claims instanceof Array) {
    packedClaims = [];
    const recursivelyPackedClaims = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
        const idx = parseInt(key);
        const packed = await packSDJWT(
          claims[idx],
          disclosureFrame[idx] as DisclosureFrame,
          hasher,
          options,
        );
        recursivelyPackedClaims[idx] = packed.claims;
        disclosures = disclosures.concat(packed.disclosures);
      }
    }

    for (let i = 0; i < (claims as Array<any>).length; i++) {
      const claim = recursivelyPackedClaims[i]
        ? recursivelyPackedClaims[i]
        : claims[i];
      if (sd?.includes(i)) {
        const { hash, disclosure } = await createDisclosure(
          { value: claim },
          hasher,
          options,
        );
        packedClaims.push({ '...': hash });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }

    const decoys = createDecoy(
      disclosureFrame[SD_DECOY_COUNT],
      hasher,
      options?.generateSalt,
    );
    decoys.forEach((decoy) => {
      packedClaims.push({ '...': decoy });
    });
  } else {
    packedClaims = {};
    const recursivelyPackedClaims = {};
    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
        const packed = await packSDJWT(
          claims[key],
          disclosureFrame[key] as DisclosureFrame,
          hasher,
          options,
        );
        recursivelyPackedClaims[key] = packed.claims;
        disclosures = disclosures.concat(packed.disclosures);
      }
    }

    const _sd: string[] = [];

    for (const key in claims) {
      const claim = recursivelyPackedClaims[key]
        ? recursivelyPackedClaims[key]
        : claims[key];
      if (sd?.includes(key)) {
        const { hash, disclosure } = await createDisclosure(
          { key, value: claim },
          hasher,
          options,
        );
        _sd.push(hash);
        disclosures.push(disclosure);
      } else {
        packedClaims[key] = claim;
      }
    }

    const decoys = createDecoy(
      disclosureFrame[SD_DECOY_COUNT],
      hasher,
      options?.generateSalt,
    );
    decoys.forEach((decoy) => {
      _sd.push(decoy);
    });

    if (_sd.length > 0) {
      packedClaims[SD_DIGEST] = _sd.sort();
    }
  }
  return { claims: packedClaims, disclosures };
};
