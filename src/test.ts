import SdJwt, { SDJwtInstance } from './index';

(async () => {
  const payload = {
    first_name: 'lukas',
    last_name: 'Han',
  };

  const diclosureFrame = {
    _sd: ['first_name', 'last_name'],
  };

  const sdjwt = await SdJwt.issue(payload, diclosureFrame);
  /*
{
  header: {
    alg: 'EdDSA',
    typ: 'sd-jwt
  },
  payload: {
    _sd: [
      'C9inp6YoRaEXR427zYJP7Qrk1WH_8bdwOA_YUrUnGQU',
      'Kuet1yAa0HIQvYnOVd59hcViO9Ug6J2kSfqYRBeowvE',
    ],
    "_sd_alg": "sha-256"
  }
  signature: <Buffer 23 43 ...>,
  disclosures: [
    Disclosure {
      salt: '2s0ecJLoIRYsI6fiLh2Rmw',
      key: 'first_name',
      value: 'lukas',
      _digest: '2nSYrhcosKKF3afJm59vJScSda5PR67vegfMMfFwcgU'
    },
    Disclosure {
      salt: 'GStG846slDv3qbEXTN2DuA',
      key: 'last_name',
      value: 'Han',
      _digest: 'LNjub6UQwsiKkeHXJ9Izev59POudSvBMSBYRQaoBOGg'
    },
  ]
}
  */
  const credential = SdJwt.encode(sdjwt);

  /////////////////////////////////////////////////////////////

  const presentationFrame = {
    _sd: ['last_name'],
  };
  const encodedPresentSdjwt = await SdJwt.present(
    credential,
    presentationFrame,
  );
  /*
eyJhbGciOiJFZERTQSJ9.eyJpZCI6ImRpZDpleGFtcGxlOmIzNGNhNmNkMzdiYmYyMyIsInR5cGUiOlsiUGVybWFuZW50UmVzaWRlbnQiLCJQZXJzb24iXSwiZ2l2ZW5OYW1lIjoiSk9ITiIsIm9iIjp7ImIiOnsiYyI6IjIiLCJkIjp7Il9zZCI6WyJrSlEwcjBjMjV5blM2cjJYYnJWOERFSm9ZVkRETHNwM1plY1duVjVlZTQ4Il19fSwiX3NkIjpbImh5eUxZWjhEa19rZXJNVzhOVWZnTmRxbEdxVkg5MTI1b0ZPTnhnVkZCa3MiXX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIjF3TUlhZnM5WDBGZW1uelRuWHBER0IyZmN3WUdiZXVSU3Z2VzhlZzhhTVUiLCIyblNZcmhjb3NLS0YzYWZKbTU5dkpTY1NkYTVQUjY3dmVnZk1NZkZ3Y2dVIiwiRmlxUlg1V18zQnpUYU1lMXVmZUR5aDBSa3J5TmVzODEtdXZpR2t6OXdJZyIsIkxOanViNlVRd3NpS2tlSFhKOUl6ZXY1OVBPdWRTdkJNU0JZUlFhb0JPR2ciLCJOcjBiMTJqcjVvdXItVlVMdTBXSGZKVVVCazBmbEppMWZ3Wms2ZE14bFE0IiwiUVpTOUZwZjJ2eFN5alU5WnNsWGNTQU5kVW42MEs3bWVEb2JPQWRlRUtJNCIsIlNQWUg2ZTB5YWhoc05fSUhzVmNGQXR4WUJOSmFpVlpfRDBoRXluUWd3cmMiLCJ2blAyX3RFQ01MU0pQNzZ3ZHlicTgxdE1JWFNkclZnU3lHVzdVNkJ6emQwIiwid0J1UjliVXd2Vl9tRXh1QzVvOWg2Y1dGVkVPLWV1ajV3WFJybDdmU3ZiYyJdfQ.I44GNgMgFFQNYS-XbwWhTvxajndisKgsu9H2xdGPID8gnOBqvA1SLJ9Kkg44eS2RUz-O5bltWdNBsQc2TwGiCg~WyIyczBlY0pMb0lSWXNJNmZpTGgyUm13IiwiaW1hZ2UiLCJkYXRhOmltYWdlL3BuZztiYXNlNjQsaVZCT1J3MEtHZ29rSmdnZz09Il0~WyJHU3RHODQ2c2xEdjNxYkVYVE4yRHVBIiwiZ2VuZGVyIiwiTWFsZSJd~WyJYZUZmTGxzdEpuMklfc3ctS21QRkJ3IiwiYmlydGhDb3VudHJ5IiwiQmFoYW1hcyJd~
  */

  const result = await SdJwt.verify(encodedPresentSdjwt, { last_name: true });
  console.log(result);
  // true
  // need to what cause failure? @Ace

  ///////////////////////////////////////////////////////////////////////////////////

  const mySDJwtInstance: SDJwtInstance = SdJwt.create({ omitTyp: true });
  mySDJwtInstance.config({ omitDecoy: true });

  // ... using mySDJwtInstance to issue, present, verify SDJwt
})();
