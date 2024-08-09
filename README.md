# ByteCrypt

**Single-Translation-Unit**


### Description

**Compatibility**, **c++ version**
The code is designed to work on a 64-bit x86-64 architecture, specifically on Linux and macOS operating systems, using C++14 or C++17, with a compiler version of GCC 5.1 or later, or Clang 3.6 or later.

This is a C++ implementation of a cryptographic library called ByteCrypt. It's a collection of tools and functions that allow you to perform various cryptographic operations, such as encryption, decryption, hashing, and digital signatures.

The library is organized into a namespace called ByteCryptModule, which makes it easy to use and integrate into your own projects. It uses the widely respected Crypto++ library as its underlying cryptographic engine.

One of the key features of ByteCrypt is its support for multiple encryption algorithms, including AES, Blowfish, and Twofish, in both CBC (Cipher Block Chaining) and GCM (Galois/Counter Mode) modes. This gives you a lot of flexibility when it comes to choosing the right encryption algorithm for your specific needs.

In addition to encryption, ByteCrypt also provides a range of hashing functions, including SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512. These functions make it easy to generate digital fingerprints of data, which can be used to verify its integrity and authenticity.

The library also includes tools for generating and verifying digital signatures, which are used to authenticate the sender of a message and ensure that the message has not been tampered with. This is done using RSA and DSA algorithms, which are widely used and respected in the industry.

## some basic cryptography...

Often people make confusion between hashing and encryption, but encryption and hashing are two distinct concepts in cryptography. Encryption is a two-way process that transforms plaintext data into unreadable ciphertext to protect it from unauthorized access, and then transforms it back into plaintext when the authorized party needs to access it. On the other hand, hashing is a one-way process that takes plaintext data and transforms it into a fixed-length string of characters, known as a hash value or digest, that can't be reversed or transformed back into the original plaintext data, and is often used for data integrity, authenticity, and password storage purposes.

## Hashing and Encryption

Hashing and encryption are two fundamental concepts in the field of cryptography. Hashing is a one-way process that transforms a variable-length input into a fixed-length string of characters, known as a hash value or digest. This transformation is irreversible, meaning that it is computationally infeasible to reverse engineer the hash value to obtain the original input.

### Hashing

Hashing is a valuable tool for verifying the integrity of data. It is used to detect any changes or tampering with the data. The process of hashing involves passing the input data through a hashing algorithm, such as SHA-256 or MD5. The resulting hash value is a unique string of characters that represents the input data.

### Encryption

Encryption is a two-way process that transforms plaintext data into unreadable ciphertext. This process is used to protect data from unauthorized access, ensuring confidentiality and security. Encryption involves using a cryptographic algorithm, such as AES or RSA, to transform the plaintext data into ciphertext. The ciphertext can only be deciphered with the decryption key.

## Digital Signatures

A digital signature is a cryptographic mechanism that verifies the authenticity of a message or document. The process involves hashing the message and then encrypting the hash value with the sender's private key. The resulting encrypted hash value is attached to the message as a digital signature.

### RSA Encryption

RSA encryption is a widely used public-key encryption algorithm. It involves generating a pair of keys, a public key and a private key. The public key is used to encrypt the data, while the private key is used to decrypt the data.

### CBC Mode and GCM Mode

CBC (Cipher Block Chaining) mode and GCM (Galois/Counter Mode) mode are two commonly used modes of operation for block ciphers. CBC mode involves encrypting each block of plaintext data independently, while GCM mode involves encrypting the plaintext data in parallel.

### Base64 and Hex Encoding/Decoding

Base64 and hex encoding/decoding are two common methods of encoding and decoding binary data. Base64 encoding involves converting binary data into a string of characters, while hex encoding involves converting binary data into a hexadecimal string.

**Security Considerations**

It is essential to consider the security implications of using hashing and encryption. A secure hashing algorithm should be collision-resistant and pre-image resistant. A secure encryption algorithm should be resistant to known-plaintext attacks and chosen-ciphertext attacks.

### References

    "Hash Functions" by the National Institute of Standards and Technology (NIST)
    "Encryption" by the International Organization for Standardization (ISO)
    "Digital Signatures" by the Internet Engineering Task Force (IETF)
    "RSA Encryption" by the RSA Security Inc.
    "CBC Mode" by the National Institute of Standards and Technology (NIST)
    "GCM Mode" by the National Institute of Standards and Technology (NIST)
    "Base64 Encoding" by the Internet Engineering Task Force (IETF)
    "Hex Encoding" by the International Organization for Standardization (ISO)


## Public Member Functions


* hash
* cbc_encrypt
* cbc_decrypt
* gcm_encrypt
* gcm_decrypt
* base64_encode
* base64_decode
* hex_encode
* hex_decode
* generate_rsa_key_der_pair
* generate_rsa_key_pem_pair
* sign_message
* verify_signature
* save_rsa_key
* load_rsa_key



## Enum

```cpp
enum class e_hash_algo_option
{
    SHA1 = 0,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
};

enum class e_rsa_key_pem_version
{
    PUBLIC = 0,
    PRIVATE
};

enum class e_symmetric_algo
{
    AES = 0,
    BLOWFISH,
    TWOFISH,
    CAST128,
    CAST256,
    IDEA,
    RC2,
    RC5,
    RC6,
    MARS,
};
```


## Struct
```cpp
typedef struct alignas(void *)
{
    std::optional<string_t> public_key{std::nullopt};
    std::optional<string_t> private_key{std::nullopt};
    bool state{false};
} rsa_key_pair_struct;

typedef struct alignas(void *)
{
    string_t key{};
    string_t error{};
    bool status{false};
} rsa_key_block_load;
```


## Examples

### Hashing
> optional paramater(2) values:
* e_hash_algo_option::SHA1
* e_hash_algo_option::SHA224
* e_hash_algo_option::SHA256
* e_hash_algo_option::SHA384
* e_hash_algo_option::SHA512
  
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt; // create new instance of ByteCrypt

string buffer = "your mother"; // some random text to hash

string hashed = bCrypt.hash(buffer); // default hash with SHA256

std::cout << "Hashed: " << hashed << "\n"; // print result

return 0;

}
```

### CBC Encryption
> CBC mode encryption
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string buffer = "your mother"; // buffer to encrypt using "secret" key

string secret = "secret_key_for_decryption"; // this is the key used for encryption/decryption

string encrypted = bCrypt.cbc_encrypt(buffer, secret, e_symmetric_algo::AES); // encrypt buffer block and return result

std::cout << "encrypted: " << encrypted << "\n"; // print result

return 0;

}
```

### CBC Decryption
> CBC mode decryption
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string buffer = "urmother cbc mode";

string secret = "secret_key_for_decryption";

string encrypted = bCrypt.cbc_encrypt(buffer, secret, e_symmetric_algo::AES);

std::cout << "encrypted: " << encrypted << "\n";

string decrypted = bCrypt.cbc_decrypt(encrypted, e_symmetric_algo::AES);

std::cout << "decrypted: " << decrypted << "\n";

return 0;

}
```

## GCM Encryption vs CBC Encryption

CBC (Cipher Block Chaining) and GCM (Galois/Counter Mode) are two modes of operation for symmetric-key block ciphers. In CBC, each block of plaintext is encrypted independently using the previous block's ciphertext as an initialization vector (IV). The IV is typically generated randomly and prepended to the ciphertext. While CBC is simple and efficient, it's vulnerable to certain attacks, such as block replay attacks and chosen-plaintext attacks.

GCM, on the other hand, combines a block cipher with a counter-based mode. Each block is encrypted using a block cipher, and a counter value is incremented for each block. The ciphertext is then authenticated using a Galois field (finite field) operation. This provides both confidentiality and integrity, as it authenticates the ciphertext and detects tampering. GCM is more secure than CBC due to its authentication mechanism, but it's also more computationally intensive.

Overall, the main difference between CBC and GCM is that GCM provides authentication, while CBC does not. This makes GCM a better choice for applications that require both confidentiality and integrity, such as secure communication protocols. In contrast, CBC may be sufficient for applications that only require confidentiality, such as data storage.

### GCM Encryption/Decryption example
> they are actually very similar.
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string buffer = "urmother gcm mode";

string secret = "secret_key_for_decryption";

string encrypted = bCrypt.gcm_encrypt(buffer, secret, e_symmetric_algo::AES);

std::cout << "encrypted: " << encrypted << "\n";

string decrypted = bCrypt.gcm_decrypt(encrypted, e_symmetric_algo::AES);

std::cout << "decrypted: " << decrypted << "\n";

return 0;

}
```

### Encoding/Decoding
> encoding schemes are:

* base64
* hex
  
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;
string buffer = "plain text";
string base64_encode = bCrypt.base64_encode(buffer);
string base64_decode = bCrypt.base64_decode(base64_encode);
string hex_encode = bCrypt.hex_encode(buffer);
string hex_decode = bCrypt.hex_decode(hex_encode); 

return 0;

}
```

### RSA Key Generation
> Generate a pair of RSA Key Pair(DER)
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

// generate RSA 2048 BS kp(key-pair) in DER format and store value into structure(rsa_key_pair_struct)
const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(2048); // 512, 1024, 2048, 3072, 4096

// using keys...
const string public_key  = key_pair.public_key;   // public key string
const string private_key = key_pair.private_key;  // private key string

return 0;

}
```

### RSA Key Generation
> Generate a pair of RSA Key Pair(PEM)
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){
const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_pem_pair(2048);
}
```

### RSA Key Store/Load

> store or load RSA keys...
  
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(3072); // 3072 BS

const string public_key  = key_pair.public_key,  private_key = key_pair.private_key;

// --- Store ---
bCrypt.save_rsa_key("/home/user/Documents/RSA/priv.pem", key_pair.private_key.value()); // private_key has optional value...
bCrypt.save_rsa_key("/home/user/Documents/RSA/pub.pem", key_pair.public_key.value());

// --- Load ---
const rsa_key_block_load gpublic_key = bCrypt.load_rsa_key("/home/user/Documents/RSA/pub.pem"); // rsa_key_block_load is a struct returning:

return 0;
}
```


### Signature, verification...

> block signing with private key, signature generation, signature verification, message authentication, message signing, etc...
  
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(3072); // 3072 BS

const string public_key  = key_pair.public_key,  private_key = key_pair.private_key;

// either use load_rsa_key() or generate keys to sign and verify

// ------------- Fresh Generate --------------
ByteCryptModule::ByteCrypt byte_crypt;
{
	rsa_key_pair_struct rsa_keys = byte_crypt.generate_rsa_key_der_pair(2048);
	bc.save_rsa_key("/home/user/Documents/RSA/pub.pem", rsa_keys.public_key.value());
	bc.save_rsa_key("/home/user/Documents/RSA/priv.pem", rsa_keys.private_key.value());
}

// ------------- OR LOAD ---------------
ByteCryptModule::rsa_key_block_load rsa_private_key = byte_crypt.load_rsa_key("/home/user/Documents/RSA/priv.pem");
ByteCryptModule::rsa_key_block_load rsa_public_key = byte_crypt.load_rsa_key("/home/user/Documents/RSA/pub.pem");

if (!rsa_public_key.status || !rsa_private_key.status)
    return EXIT_FAILURE;

// --- PREPARE MESSAGE ---
std::string private_key = rsa_private_key.key, public_key = rsa_public_key.key;
std::cout << "RSA Private Key: " << rsa_private_key.key << std::endl;
std::string message = "This is a test message.";

// --- SIGN MESSAGE ---
std::string signature = byte_crypt.sign_message(message, private_key);
if (signature.empty()) return EXIT_FAILURE;
std::cout << "Signature: " << signature << std::endl;

// --- VERIFY SIGNATURE/MESSAGE ---
bool is_verified = byte_crypt.verify_signature(message, signature, public_key);
if (is_verified) std::cout << "Signature verification succeeded." << std::endl;
else std::cerr << "Signature verification failed." << std::endl;

return 0;

}
```


## Disclaimer Of Warranty

/**
 * ============================================================================
 * ByteCrypt Class - A C++ Data Encryption Utility Module
 * ============================================================================
 *
 * DISCLAIMER OF WARRANTY:
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the author(s) be held liable for any damages arising from
 * the use of this software, including but not limited to:
 *
 * - Loss of data
 * - Any other type of loss or damage
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would
 *    be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not
 *    be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * LIMITATION OF LIABILITY:
 *
 * In no event will the author(s) be liable for any damages, including but
 * not limited to incidental, consequential, or punitive damages, arising
 * out of the use of this software.
 *
 * COPYING AND DISTRIBUTION:
 *
 * This software may be copied and distributed free of charge, provided
 * that the above copyright notice, disclaimer, and limitations of liability
 * are included in all copies.
 *
 * AUTHORIZATION:
 *
 * By using this software, you acknowledge that you have read and understood
 * the terms and conditions of this license, and agree to be bound by them.
 *
 * TRADEMARKS:
 *
 * The names of actual companies and products mentioned in this software
 * may be the trademarks of their respective owners.
 *
 * ACKNOWLEDGMENT:
 *
 * The authors would like to acknowledge the contributions of the C++
 * community, and the many individuals who have helped shape the C++
 * standard library.
 *
 * ============================================================================
 *
 * Written by [Somorpher], [2024].
 */
