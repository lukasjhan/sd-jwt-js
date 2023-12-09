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

import { pack } from './sdjwt';

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
