# node-dynamic-argon2d
Usage
------
to create a raw hash from a string of data 
```js
var argon2d = require('node-dynamic-argon2d');
var buf = Buffer.from("someString", 'utf8');
var hash = argon2d.argon2d(buf);
console.log(hash);
//should return <Buffer 0d 01 c4 09 bd 11 f1 07 d0 e9 41 ca c3 bd bf 3e ed 02 0f 9e ca d2 2b 8a 8f a0 eb 3a e2 2c b1 e0>
```