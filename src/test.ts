import { Jwt } from './jwt';
import { DefaultSigner } from './crypto';

const jwt = new Jwt();
const signer = new DefaultSigner();
console.log('pubkey:', signer.getPublicKey());

jwt
  .setHeader({
    alg: 'EdDSA',
    typ: 'JWT',
  })
  .setPayload({
    iss: 'https://example.com',
    iat: 1300019380,
  })
  .setSigner(signer.getSigner());

(async () => {
  await jwt.sign();
  const str = jwt.serialize();
  console.log(str);
  const jwt2 = Jwt.fromCompact(str);
  console.log(jwt2);
  jwt2.setVerifier(signer.getVerifier());
  const ret = await jwt2.verify();
  console.log(ret);
})();
