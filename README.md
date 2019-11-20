# **Argon2d Dynamic**

![DYN logo](https://github.com/duality-solutions/Dynamic/blob/master/src/qt/res/icons/drk/about.png)

**Copyright (c) 2016-2019 [Duality Blockchain Solutions](https://duality.solutions/)**

What is node-dynamic-argon2d?
-----------------------------
A Node.js module of the Argon2d hashing parameters used in Dynamic (DYN).


Installation Instructions
-------------------------

It is available to install via the Node.js Package Manager (NPM) by using the command:

```$ npm install argon2d-dynamic```

or by cloning from Github and installing locally using NPM:

```$ git clone https://github.com/duality-solutions/argon2d-dynamic```

```$ cd argon2d-dynamic```

```$ npm install```


Usage
-----
to create a raw hash from a string of data 
```js
var argon2d = require('argon2d-dynamic');
var buf = Buffer.from("someString", 'utf8');
var hash = argon2d.argon2d(buf);
console.log(hash);
//should return <Buffer 0d 01 c4 09 bd 11 f1 07 d0 e9 41 ca c3 bd bf 3e ed 02 0f 9e ca d2 2b 8a 8f a0 eb 3a e2 2c b1 e0>
```

License
-------
Work licensed under the [MIT License](LICENSE). Please check
[P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) for
license over Argon2 and the reference implementation.
