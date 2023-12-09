/*
import { Frame } from './type';

function a<T>(payload: T, frame: Frame<T>) {
  console.log(payload, frame);
}

const claims = {
  firstname: 'John',
  lastname: 'Doe',
};

a(claims, {
  _sd: ['firstname'],
});

const claims2 = {
  address: {
    street: '123 Main St',
    suburb: 'Anytown',
    postcode: '1234',
  },
};

a(claims2, {
  address: {
    _sd: ['postcode'],
  },
});

const claims3 = {
  nicknames: ['Johnny', 'JD'],
};

a(claims3, {
  nicknames: {
    _sd: [0],
  },
});

const claims4 = {
  items: [
    {
      type: 'shirt',
      size: 'M',
    },
    'hi',
  ],
};

a(claims4, {
  items: {
    0: {
      _sd: ['size', 'type'],
    },
    _sd: [1],
  },
});
*/

/*
import { Disclosure } from './disclosure';
import { pack, unpack } from './sdjwt';

function A() {
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
  };

  const { packedClaims, disclosures } = pack(claims, {
    _sd: ['lastname', 'firstname'],
  });

  console.log(packedClaims, disclosures);
}

function B() {
  const claims = {
    address: {
      street: '123 Main St',
      suburb: 'Anytown',
      postcode: '1234',
    },
  };

  const { packedClaims, disclosures } = pack(claims, {
    address: {
      _sd: ['postcode'],
    },
    _sd: ['address'],
  });

  console.log(packedClaims, disclosures);
}

function C() {
  const claims = {
    nicknames: ['Johnny', 'JD'],
  };

  const { packedClaims, disclosures } = pack(claims, {
    nicknames: {
      _sd: [0],
    },
  });

  console.log(packedClaims, disclosures);
}

function D() {
  const claims = {
    items: [
      {
        type: 'shirt',
        size: 'M',
      },
      'hi',
    ],
  };

  const { packedClaims, disclosures } = pack(claims, {
    items: {
      0: {
        _sd: ['size'],
      },
      _sd: [1],
    },
  });

  console.log(packedClaims, disclosures);
}

A();
console.log('================================================================');
B();
console.log('================================================================');
C();
console.log('================================================================');
D();

function E() {
  const sdjwt = {
    nicknames: [
      {
        '...':
          'ZTM0YjdhZTg4ODliNDkwMDNkZjFlMWU2OTE0NTlhZDk3OGJkMDc4MmE0ZWE1YmYwMTRkNTI5NDU0MGM0ZTE3OA',
      },
      'JD',
    ],
  };

  const disclosures = [
    new Disclosure(['452c6bca32bdaeb6ea1d9282e63e9369', 'Johnny']),
  ];

  const ret = unpack(sdjwt, disclosures);
  console.log(ret);
}
console.log('unpack:');
E();
*/

import sdjwt from './index';
import * as jose from 'jose';

(async () => {
  const encodedSdjwt = await sdjwt.issue(
    {
      firstname: 'John',
      lastname: 'Doe',
    },
    {
      _sd: ['firstname'],
    },
  );
  console.log(encodedSdjwt);
  const validated = await sdjwt.validate(encodedSdjwt);
  console.log(validated);

  const secret = new TextEncoder().encode(
    'cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2',
  );

  const alg = 'HS256';

  const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
    .setProtectedHeader({ alg })
    .sign(secret);
  console.log(jwt);
  const verified = await jose.jwtVerify(jwt, secret);
  console.log({ verified });
  const payload = jose.decodeJwt(jwt);
  console.log(payload);
})();
