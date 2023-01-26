---
layout: post
title:  "Symmetric Encryption in JavaScript for PII: Best Practices for PII Data Protection"
date:   2023-01-26 00:00:00 -0300
categories: cryptography javascript security
---

# Disclaimer

While this article provides an overview of symmetric encryption and its implementation using standard JavaScript libraries, it should not be considered a substitute for a thorough security review by an expert. Many excellent options for IaS and SaaS offer encryption and protection for PII data services, including key management. Even when using standard algorithms and libraries, it's essential to have professional support to ensure the security level of your cryptographic system. This article introduces the topic and should be supplemented with further learning and research. The references and related articles help guide your understanding and decision-making when choosing the best service or approach to complement your cryptosystem and enhance its security.

# Introduction

This article builds upon the concepts discussed in my previous article, "[4 Ways of Symmetric Cryptography and JavaScript: How to AES with JavaScript](https://dev.to/halan/4-ways-of-symmetric-cryptography-and-javascript-how-to-aes-with-javascript-3o1b)" published in Sep 2019. It will delve into a specific application of previously covered techniques, utilizing only standard APIs. While some key concepts may be briefly reviewed, it is assumed that the reader has already read the aforementioned article. The main focus of this one will be the exploration of a specific use case: PII Data Protection.

Protecting personal identification information (PII, [https://www.dol.gov/general/ppii](https://www.dol.gov/general/ppii)) is of the utmost importance today. One of the most effective ways to safeguard sensitive data is through encryption. This article will focus on symmetric encryption and explore the options available within JavaScript environments.  With symmetric encryption, the same key is used for encrypting and decrypting data. This is suitable for cases where the same party that stores the data will also be responsible for reading it, eliminating the need for separate encryption and decryption keys.

We will explore the basics of symmetric encryption, delving into fundamental concepts such as Advanced Encryption Standard (AES, [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)), Password-Based Key Derivation Function 2 (BPKDF2, [RFC 2898](https://datatracker.ietf.org/doc/html/rfc2898)) and scrypt ([RFC7914](https://www.rfc-editor.org/rfc/rfc7914)) explaining how they work together to secure data. We will also provide code examples of symmetric encryption implemented using JavaScript standard libraries for Node.js and also talk about encryption on the browser. Additionally, we will discuss best practices for protecting PII data and the key distribution problem that arises with symmetric encryption.

I choose AES here, but Node.js interfaces directly with OpenSSL, which means it can operate with any other supported algorithm. To see a complete list of available algorithms, you can run `openssl list -cipher-algorithms` and check for yourself. You will see different key lengths and operating modes listed as available algorithms, along with some shortcuts.

# What is PII?

PII is any information that can be used to identify an individual. Regarding sensitive data, PII is among the most important to protect. The loss or unauthorized access to PII can have serious consequences, such as identity theft, financial fraud, and reputational damage. Examples of PII include, but are not limited to:

- Full name
- Social Security number
- Date of birth
- Address
- Phone number
- Email address
- Driver's license number
- Passport number
- Financial information (credit card numbers, bank account numbers, etc.)

PII can take many forms and be collected in various ways. For example, PII can be collected online through websites and social media, over the phone, by mail, or in person. It's also important to note that PII can be combined with other data to create a more detailed profile of an individual, making it even more sensitive and valuable to attackers.

Various laws and regulations are in place to protect PII worldwide. These laws vary depending on the country and jurisdiction, but they aim to protect individuals' privacy and personal information from unauthorized access, use, disclosure, alteration, or destruction. Those juridic details and analyses are out of my scope here.

# Let's encrypt it at all times!

There may be instances where your application must store PII data to use it. This storage can occur in the browser, such as in `LocalStorage` or cookies, or on your backend, which is more commonly used in most systems. In either case, your application is responsible for protecting this data. One way to safeguard stored PII data is by always encrypting it.

HTTPS/SSL can secure the connection between the client and server, but it does not protect the stored data. To ensure the protection of PII data, it is necessary to implement an additional layer of encryption at the application level. Furthermore, minimizing PII data storage and avoiding storing it in logs is essential. This can help prevent unauthorized access and use of the data. Also, remember that even when storing data in an encrypted format, if an attacker can execute commands on your production environment, they may bypass your encryption or steal your keys. Therefore, it is essential to have secure systems in place to protect against data leaks and unauthorized access and utilize the encryption techniques discussed in this article.

This section will discuss the two standard encryption APIs available in the primary JavaScript environments: web browsers and Node.js. It's worth noting that encryption APIs are widely available in various programming languages, and they typically rely on compiled encryption modules, such as OpenSSL, to perform the encryption process.

Regarding encrypting and decrypting data on the backend, this process can be done before storing the data in any database. I recommend generating a unique key for each register/customer. Key generation is an entire topic in cryptography, and we'll return to this subject on the following topics. Hashing algorithms are commonly used for that process and act as Pseudo Number Generators (PNG). Most cryptography APIs also provide a PNG to generate random numbers with a cryptographic level of security that can be used to generate keys. For Node.js we'll rely on `crypto.randomBytes` or the most recent `crypto.randomFill`.

Let's examine some code examples for generating keys and encrypting plain data. Afterward, I will provide further explanations and insight into important concepts related to this process:

```jsx
const crypto = require('crypto');

// It's a good pratice to convert all elements to Buffer
const passphrase = Buffer.from("this can be more than a pass-word, it must be a pass-phrase");

// Alloc two buffers of 128 bits to be used as salt and iv
const salt = Buffer.alloc(128/8);
const iv = Buffer.alloc(128/8);

// Fill the salt buffer; remember, different salts will drviate different keys
crypto.randomFillSync(salt);

// Fill the IV buffer; remember, it'll be used by the operation mode GCM,
// and each encryption must use a random IV
crypto.randomFillSync(iv);

// Generate a 256-bit key from the passphrase and salt
// the key will be a Buffer
const key = crypto.scryptSync(passphrase, salt, 256/8);

console.log('Secret Key:', key.toString('base64'));
// Secret Key: 0U9nKHzpk8dMz48cF+h9WEDfrh5mGVJv2jOA3JCVM9w=

const PII = {
  fullname: "John Doe",
  email: "johndoe@acme.com"
};

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

// the plain text will be utf8, and the return will be a Buffer
const enc = Buffer.concat([
  cipher.update(JSON.stringify(PII), 'utf8'),
  cipher.final()
]);

const auth = cipher.getAuthTag();

// Having all elements already on buffer format, we can choose a string format like base64 or hex, avoiding utf8 representing non-chars bytes.
console.log('Encrypted data to store:', JSON.stringify({
  enc: enc.toString('base64'),
  auth: auth.toString('base64'),
  iv: iv.toString('base64'),
  salt: salt.toString('base64')
}));
// Encrypted data to store: {"enc":"p8KndPBXz4CuroZgUnj3l3I3aqD4Cu+EPzLFOCc+gkh4ikmeSg60mtxerQt7/7dRPF8=","auth":"cA4ibtnsftkWqDZnutI3kQ==","iv":"BOlQb5etEWcEXh+j0+Habw==","salt":"G/O/rk0r1x7mlafEHLPKsw=="}

```

When expressing key lengths in my code, I prefer to use bits for the key length instead of bytes. For example, instead of just saying `32` bytes, I would express it as `256/8` for the AES algorithm `aes-256-gcm`. This makes it clear that the key size is expressed in bits and is consistent with the naming convention of the algorithm. AES also supports keys 128 and 192. It's directly related to the encryption rounds.

To decrypt the data, we need to generate the same key using the same key derivation function. Then, we will input the base64 encoded data into the decryption function.

```jsx
const crypto = require('crypto');

const encryptedFields = {
  enc: "p8KndPBXz4CuroZgUnj3l3I3aqD4Cu+EPzLFOCc+gkh4ikmeSg60mtxerQt7/7dRPF8=",
  auth: "cA4ibtnsftkWqDZnutI3kQ==",
  iv: "BOlQb5etEWcEXh+j0+Habw==",
  salt: "G/O/rk0r1x7mlafEHLPKsw=="
};

// Let's put all data as buffers to be able to use them directly on crypto functions
const enc = Buffer.from(encryptedFields.enc, 'base64');
const auth = Buffer.from(encryptedFields.auth, 'base64');
const iv = Buffer.from(encryptedFields.iv, 'base64');
const salt = Buffer.from(encryptedFields.salt, 'base64');

// All the secret of that encryption relying on that string
// It's usually memorized or stored in a safe place
// but if you're able to store that, would be better a non-memorizable string
const passphrase = Buffer.from("this can be more than a pass-word, it must be a pass-phrase");

// Recover the key from the passphrase memorized and salt stored
const key = crypto.scryptSync(passphrase, salt, 256/8);

console.log('Secret Key:', key.toString('base64'));
// Secret Key: 0U9nKHzpk8dMz48cF+h9WEDfrh5mGVJv2jOA3JCVM9w=

const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

decipher.setAuthTag(auth);

// the .final() should fail if the Auth Tag is wrong, but the update 
// will can decipher since the key is correct
const data = decipher.update(enc) + decipher.final();

console.log('JSON object decyphered:', JSON.parse(data));
// { fullname: 'John Doe', email: 'johndoe@acme.com' }

```

# Key Derivation

A key management method can also be implemented through IaaS with a high level of security. However, it can also be done by encrypting the session key (the key generated for each record) with a master key, which could also be rotated and identified by a part of it hashed.

This master key can also be derived from a password through PBKDF. In the past, I have recommended using PBKDF2 for deriving keys. This algorithm uses extensive and repeated hashing to protect against brute-force attacks. However, there is now a more attractive alternative called scrypt, which includes a memory-hard function to slow down and discourage brute-force attempts by increasing each calculation's memory and processing costs. This algorithm was recently added to Node.js (version 10.5.0, Dec 2018) and is particularly useful due to the increasing power of hardware-based hashing calculations in recent years. For more details and recommendations regarding PBKDF, [check that document](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf).

When choosing a key derivation function for your Node.js backend, it's important to consider the security schema in place and the origin of the password or seed being used. While scrypt is a solid alternative to traditional options such as PBKDF2, it's worth noting that browser support for scrypt through the WebCrypto API is currently not yet standardized. Also, It does not make sense to derive a key based on a backend password and then derive the same key from the password on the frontend. A password cannot be a shared secret. Instead, the frontend password key derivation should only be used when a user-typed password is necessary to derive a key. Be sure to check for browser compatibility and available polyfills. Additionally, remember that these algorithms intentionally require a significant amount of computational power (depending on the settings), and care should be taken to ensure that this does not negatively impact the user experience or slow down crucial operations on your system. The key is to strike a balance between security and performance.

In terms of Node.js implementation, the `scrypt` function has both synchronous and asynchronous versions. The asynchronous version, `scrypt`, uses the older callback style instead of Promises. It can be converted to a Promise using `Utils.promisify`. Still, there is no advantage to using the asynchronous version with `await` as it will have the same behavior as the synchronous function, `scryptSync`, unless you need to run it in parallel with other tasks using `Promise.all`. It's worth noting that most key derivation functions within the crypto API also offer both synchronous and asynchronous versions.

# Operation Modes and IV

AES is a block-based encryption algorithm that processes data in chunks of 128 bits (16 bytes) at a time. An operation mode and proper padding must be used to encrypt content that is longer than one block to ensure the data fits precisely within the block size. The operation mode determines how each block of data is processed to provide a high level of security.

Regarding the available operation modes for AES, you may avoid using Eletronic CodeBook (ECB). ECB mode applies AES to each block independently, this method may be suitable for encrypting other cryptographic elements, such as keys and hashes, but it needs to be more secure for most data types. Most operation modes, such as Galois Counter Mode (GCM) and Cipher Block Chaining (CBC), use chaining, where the previous block of ciphertext is used to encrypt the next block. This creates a cascading effect, which is critical for the security of the encryption. GCM also offers the additional benefit of ensuring the authenticity and integrity of the content through the use of an auth tag, as demonstrated in the code provided. It's worth checking the [Wikipedia page](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) about operation modes for a quick explanation of each algorithm. 

Additionally, these modes use an Initialization Vector (IV), a cryptographically random value used in the encryption process, and should never be reused. The IV acts as the first block and should be 128 bits for AES, regardless of the key length. The IV should be known and stored alongside the encrypted data to allow for decryption, but it is not considered a security risk as it is designed to be shared.

# On the browser

When it comes to encrypting data from the browser, it can help to store sensitive information on the client, such as in `LocalStorage`. However, encryption on the backend before storage is not directly related to encryption on the frontend. If a key needs to be shared between the frontend and backend, consider using asymmetric encryption to securely wrap the key and ensure that the key is never reused.

Recent updates in this topic include the requirement of a secure context for webcrypto functions in most browsers. This means that all functions are under `crypto.subtle` will only work on an HTTPS connection with valid and trusted certificates (aka [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)). And now, Node.js also implements the web crypto API, which allows for easy reuse of code between browser and server environments, server-side rendering, for example. This means that you can use the same code for encryption in both environments without needing to make adjustments.

```
const { webcrypto } = require('crypto');
// now you can use webcrypto.subtle exactly like on the browser

```

# Indexing encrypted data and formats

Deciding what to store and how to store encrypted data in a database is a design decision that may depend on the specific cryptosystem being used. It's important to remember that the master key should never be stored in the same environment as the database data, and all communication between them should be encrypted and protected by SSL. With that in mind, one option is to store the entire cipher, IV, and salt in a single field as a JSON object and represent the binary data as base64. While adding another layer of base64 over the JSON does not increase security, you can consider using a layer of Zlib compression over the JSON and storing the binary data as a base64 text. Regardless of the chosen extra layer of base64 or zlib, the security level remains the same.

It's also worth mentioning the JSON Web Token (JWT, [RFC7519](https://www.rfc-editor.org/rfc/rfc7519)) and its standardized format for encrypted data, known as JSON Web Encryption (JWE, [RFC7516](https://www.rfc-editor.org/rfc/rfc7516)). JWE includes headers indicating the algorithm and key identifier used, and libraries such as [JOSE](https://github.com/panva/jose) can assist in constructing this format and provide a high-level encryption interface. This can be a helpful option when working with encrypted data on JavaScript.

Once the field is encrypted, the ability to index or search by it is lost when storing encrypted data in a database. To mitigate this, you can use the same approach for passwords, such as salted hashing the data. This hashed data can then be stored alongside the encrypted PII data in a different field. The hashed data does not contain the original data and cannot be recovered, but it's perfect for searching and indexing. However, advanced, partial, or comparison searches will not be possible, but they'll be suitable for an exact match. You can also clean up the field before hashing it, such as removing dots, underscores, or spaces, providing more flexibility in searching and even accounting for minor typing errors.

# Conclusion

The primary JavaScript environments already fully support widely used cryptography primitives. The current 3rd party libraries operate at a high level, implementing best practices for cryptography and providing fallback options for legacy environments where these APIs are not yet supported.

In summary, if you need to store sensible data as PII, never do it as plain text. The same culture that we learned over the last decades of storing passwords hashed should be created to enforce encryption on PII. A data leak can be expensive for any product. Consider encrypting by yourself using symmetric encryption, but take care and keep the keys safe. As the subject of encryption and PII protection is constantly evolving, I welcome any contributions or corrections to the information presented in this article. I will make every effort to review and incorporate any suggestions to ensure that accurate and up-to-date information is shared. If you have any concerns or feedback, please don't hesitate to reach out. Your input is valuable in helping to keep this article as accurate and informative as possible.

# References and useful links

- [https://www.cossacklabs.com/blog/pii-encryption-requirements-cheatsheet/](https://www.cossacklabs.com/blog/pii-encryption-requirements-cheatsheet/)
- [https://www.dol.gov/general/ppii](https://www.dol.gov/general/ppii)
- [https://dev.to/halan/4-ways-of-symmetric-cryptography-and-javascript-how-to-aes-with-javascript-3o1b](https://dev.to/halan/4-ways-of-symmetric-cryptography-and-javascript-how-to-aes-with-javascript-3o1b)
- Cryptography and Network Security: Principles and Practice by William Stallings - [http://williamstallings.com/Cryptography/](http://williamstallings.com/Cryptography/)
- [https://www.w3.org/TR/WebCryptoAPI/](https://www.w3.org/TR/WebCryptoAPI/)
- [https://nodejs.org/api/crypto.html#crypto_crypto](https://nodejs.org/api/crypto.html#crypto_crypto)
- [https://en.wikipedia.org/wiki/PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
- [https://en.wikipedia.org/wiki/Scrypt](https://en.wikipedia.org/wiki/Scrypt)
- [https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [https://www.rfc-editor.org/rfc/rfc7914](https://www.rfc-editor.org/rfc/rfc7914)
- [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)
- [https://www.rfc-editor.org/rfc/rfc7516](https://www.rfc-editor.org/rfc/rfc7516)
- [https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
