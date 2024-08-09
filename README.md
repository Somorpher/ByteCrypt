# ByteCrypt

comprehensive cryptographic library that provides a range of cryptographic operations, including hashing using SHA1, SHA224, SHA256, SHA384, and SHA512 algorithms, encryption using AES and RSA algorithms, and digital signatures using RSA with SHA256 algorithm, along with key generation and verification functions, utilizing the Crypto++ library and designed to be highly flexible and easy to use for secure data storage, communication, and digital signatures.

## some basic cryptography...

Encryption Algorithm: AES (Advanced Encryption Standard)

Uses the AES algorithm to encrypt and decrypt data. AES is a symmetric-key block cipher that is widely used for secure data transmission. 
It is a fast and efficient algorithm that can be used for both encryption and decryption.

### how the AES algorithm works:

* Key Generation: 
> generates a random key for encryption using the __derive_key_iv function. The key is derived from a password using a password-based key derivation function (PBKDF2).
   
* Encryption:
> uses the cbc_encrypt function to encrypt a block of data using the generated key. The encryption process involves the following steps:
1) Divide the data into blocks of 16 bytes (the block size of AES).
2) Apply a random initialization vector (IV) to the first block of data.
3) Encrypt each block of data using the AES algorithm with the generated key.
4) Store the encrypted data in a buffer.

* Decryption:
> uses the decrypt function to decrypt a block of encrypted data using the same key used for encryption. The decryption process involves the following steps:
1) Divide the encrypted data into blocks of 16 bytes.
2) Apply the random IV used during encryption to the first block of encrypted data.
3) Decrypt each block of encrypted data using the AES algorithm with the same key used for encryption.
4) Store the decrypted data in a buffer.

Hashing Algorithm: SHA (Secure Hash Algorithm)

uses the SHA algorithm to generate a digital fingerprint (hash) of data. SHA is a cryptographic hash function that is widely used for data integrity and authenticity.

Here's how the SHA algorithm works:

* Hash Calculation: 
uses the hash function to calculate the hash of a block of data using the SHA algorithm. The hash calculation involves the following steps:

1) Divide the data into blocks of 64 bytes (the block size of SHA).
2) Apply a series of bitwise operations (AND, OR, XOR, etc.) to the data blocks.
3) Calculate the hash value by applying a series of modular arithmetic operations to the data blocks.
4) Store the hash value in a buffer.

* Hash Verification:

uses the verify_signature function to verify the authenticity of a block of data by comparing its hash value with a previously calculated hash value.

Signing Algorithm: RSA (Rivest-Shamir-Adleman)

uses the RSA algorithm to generate a digital signature for a block of data. RSA is a public-key encryption algorithm that is widely used for secure data transmission and digital signatures.

how the RSA algorithm works:

* Key Generation:
generates a pair of RSA keys (public and private) using the generate_rsa_key_der_pair function. The public key is used for encryption and verification, while the private key is used for decryption and signing.

1) Signing:
   * uses the sign_message function to generate a digital signature for a block of data using the private key. The signing process involves the following steps:
     1) Calculate the hash value of the data using the SHA algorithm.
     2) Encrypt the hash value using the private key and the RSA algorithm.
     3) Store the encrypted hash value (digital signature) in a buffer.
2) Verification:
   uses the verify_signature function to verify the authenticity of a block of data by comparing its digital signature with a previously calculated digital signature.

## MFunction without Signature


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


## Public Member FSignature
```cpp

string_t hash(const string_t& buffer, const e_hash_algo_option sha = e_hash_algo_option::SHA256)

string_t cbc_encrypt(const string_t& plain_text, const string_t& key, const e_symmetric_algo algo)

string_t cbc_decrypt(const string_t& cipher_block, const e_symmetric_algo algo)

string_t gcm_encrypt(const string_t& plain_text, const string_t& key, const e_symmetric_algo algo)

string_t gcm_decrypt(const string_t& cipher_block, const e_symmetric_algo algo)

string_t base64_encode(const string_t& plain_text)

string_t base64_decode(const string_t& encoded_cipher)

string_t hex_encode(const string_t& plain_text)

string_t hex_decode(const string_t& hex_encoded)

rsa_key_pair_struct generate_rsa_key_der_pair(const std::size_t rsa_key_size = 2048U)

rsa_key_pair_struct generate_rsa_key_pem_pair(const std::size_t rsa_key_size = 2048U)

string_t sign_message(const string_t& message, const string_t& private_key)

bool verify_signature(const string_t& message, const string_t& signature_str, const string_t& rsa_key)

bool save_rsa_key(const string_view_t& path, const string_t& rsa_key)

rsa_key_block_load load_rsa_key(const string_view_t& load_file)

```

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
const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(2048);

// using keys...
const string public_key  = key_pair.public_key;   // public key string
const string private_key = key_pair.private_key;  // private key string

// rsa_key_pair_struct returns a struct with the following members:
// optional<string>: public_key
// optional<string>: private_key
// bool state      : state

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
// string: key
// string: error
// bool  : status


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
