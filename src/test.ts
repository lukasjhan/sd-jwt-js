import { generateSalt, random, hash } from './crypto';

const a = generateSalt(16);
console.log(a);

const b = random(1, 5);
console.log(b);

const c = hash('2432424242432');
console.log(c);
