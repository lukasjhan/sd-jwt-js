import { createKeyPair } from './crypto';
import sdjwt from './index';

(async () => {
  const { privateKey, publicKey } = createKeyPair();
  const encodedSdjwt = await sdjwt.issue(
    {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: '1' }, 'b', 'c'],
      },
      data2: {
        hi: 'bye',
      },
    },
    privateKey,
    {
      _sd: ['firstname', 'id', 'data2'],
      data: {
        _sd: ['list'],
        list: {
          _sd: [0, 2],
          0: {
            _sd: ['r'],
          },
        },
      },
      data2: {
        _sd: ['hi'],
      },
    },
  );
  console.log(encodedSdjwt);
  const validated = await sdjwt.validate(encodedSdjwt, publicKey);
  console.log(validated);

  const decoded = sdjwt.decode(encodedSdjwt);
  console.log({ keys: decoded.keys() });
  const paylaods = decoded.getClaims();
  const keys = decoded.presentableKeys();
  console.log({
    paylaods: JSON.stringify(paylaods, null, 2),
    disclosures: JSON.stringify(decoded.disclosures, null, 2),
    claim: JSON.stringify(decoded.jwt?.payload, null, 2),
    keys,
  });

  console.log(
    '================================================================',
  );

  const res = decoded.present(['firstname', 'id']);
  console.log(res);
})();
