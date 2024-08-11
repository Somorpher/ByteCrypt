
![Logo](https://github.com/Somorpher/ByteCrypt/blob/main/images/bf322699728bf7f37e7e3c007fa0bacb_66b6bbf3aa1bc.png?raw=true)

# ByteCrypt

[![MIT License](https://img.shields.io/badge/License-MIT-red.svg)](https://github.com/Somorpher/ByteCrypt/blob/main/LICENSE) 

Versatile cryptographic utility that provides a collection of tools and functions for various cryptographic operations, including encryption, decryption, hashing, and digital signatures. Built on top of the Crypto++ library, ByteCrypt is organized within the ByteCryptModule namespace and supports multiple encryption algorithms and hashing functions.



### Mode of Operation
`CBC`  `GCM` `EAX`

### Symmetric Ciphers
`AES` `BlowFish` `twofish` `Cast128` `Cast256` `Idea` `RC2` `RC5` `RC6` `Mars` `Serpent` `GOST` `ARIA` `HIGHT` `LEA` `SEED` `SPECK128` `SIMON128`

### Asymmetric Ciphers
`RSA`

### Hash Algorithms
`SHA1` `SHA224` `SHA256` `SHA384` `SHA512`

## Acknowledgements

Knowledge of the following concepts is required:
 - [Symmetric Encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)
 - [Asymmetric Encryption](https://en.wikipedia.org/wiki/Public-key_cryptography)
 - [Block Cipher mode of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

## Proof of Concept(PoC)

> For Encryption Operation mode and algorithm testing use PE file `./test` which is `test.cpp` compiled source with g++.

> For extended test(encoding, hashing, RSA loading, Signature Based operations, etc...) use `./extended_test`.

### CBC(Cipher-Block-Counter) Operation Mode Test:
![CBC screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/f3e7ddfff8b5d18a253d571b67045a43_66b79299dc5d4.png)

### GCM(Gallois-Counter-Mode) Operation Mode Test:
![CBC screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/da566eb6adffeede444893f7c3dff25_66b79299df690.png)


### EAX Operation Mode Test:
![EAX screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/0384a7aa5e40568fdbee7ce42cc8e8_66b79299e2174.png)

### Encoding/Decoding, Hashing Test:
![RSA screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/__fdssdbe9d62418018590338bd031e6fe267d_66b7c03983097.png)

### RSA DER Key Test:
![RSA DER screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/__dfbec233575348b4d56bfbb3d4bb06e6a_66b7c03991839.png)

![RSA DER screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/__dsf98d2b400597e916d067c29de47fcf2e_66b7c0398b203.png)

### RSA PEM Key Test:
![RSA screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/__c13319a24507d90063899b6b3f477e_66b7c0398e551.png)

### RSA Key Load/Store, Signature, Verification
![RSA screenshot](https://github.com/Somorpher/ByteCrypt/blob/main/images/__ds35904dc00a3f7108fa23_66b7c0398735c.png)

All tests got successful when i tested, tested on linux mint 22, x86_64, used g++ compiler, crypto++ library installed.


## Description

ByteCrypt is a versatile cryptographic utility that provides a collection of tools and functions for various cryptographic operations, including encryption, decryption, hashing, and digital signatures. Built on top of the Crypto++ library, ByteCrypt is organized within the ByteCryptModule namespace and supports multiple encryption algorithms and hashing functions, making it a comprehensive choice for developers needing robust cryptographic solutions.
Compatibility

## Requirements

### Architecture: 64-bit, x86-64
- Operating Systems: Linux, macOS
- C++ Version: C++11 or later

### Compiler Requirements:
- GCC: 5.1 or later
- Clang: 3.6 or later
- GCC flags: -lcryptopp


### Installation of Crypto++ Library

**crypto++** is one of the most used cryptographic labriers for c++ programming, ByteCrypt relies on crypto++ mostly, crypto++ website: [cryptopp.com](https://cryptopp.com).

To use the ByteCrypt class, the Crypto++ library must be installed. Here are the installation instructions for different 
platforms:

- Debian:
```bash
sudo apt install libcryptopp-dev`
```

- Fedora:
```bash
sudo dnf install cryptopp-devel
```

- Arch:
```bash
sudo pacman -S cryptopp
```


- macOS:
```bash
brew install cryptopp
```
## Basic Cryptography Concepts:

Encryption Algorithms: Supports [AES](https://it.wikipedia.org/wiki/Advanced_Encryption_Standard), Blowfish, and Twofish in both  [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)(Cipher Block Chaining) and [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (Galois/Counter Mode) modes.
Hashing Functions: Implements SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 for generating data fingerprints.
Digital Signatures: Provides tools for generating and verifying signatures using RSA and DSA algorithms.
Base64 and Hex Encoding/Decoding: Includes methods for easy conversion of binary data.

Important Concepts
[Hashing](https://en.wikipedia.org/wiki/Hash_function) vs. [Encryption](https://en.wikipedia.org/wiki/Encryption)

Hashing: A one-way process that transforms plaintext into a fixed-length output, which cannot be reversed.
Encryption: A two-way process that converts plaintext into ciphertext, making it unreadable without a key.

Digital Signatures
A digital signature authenticates a message by hashing and encrypting the hash value with a sender&#39;s private key, ensuring integrity.
Modes of Operation

CBC Mode: Each block of plaintext is XORed with the previous ciphertext block. Requires an initialization vector (IV).
GCM Mode: Combines encryption with authentication, ensuring both confidentiality and integrity.

Security Considerations
When implementing cryptographic solutions, ensure that:

Hash functions used are collision-resistant.
Encryption algorithms are resistant to known-plaintext attacks and chosen-ciphertext attacks.

The ByteCrypt class is a collection of tools and functions that allow you to perform various cryptographic operations, such as encryption, decryption, hashing, and digital signatures. The class is organized into a namespace called ByteCryptModule. It uses the widely respected Crypto++ library as its underlying cryptographic engine.

One of the key features of the ByteCrypt class is its support for multiple encryption algorithms, including AES, Blowfish, and Twofish, in both CBC (Cipher Block Chaining) and GCM (Galois/Counter Mode) modes. This gives you a lot of flexibility when it comes to choosing the right encryption algorithm for your specific needs.

In addition to encryption, the ByteCrypt class also provides a range of hashing functions, including SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512. These functions make it easy to generate digital fingerprints of data, which can be used to verify its integrity and authenticity.

The class also includes tools for generating and verifying digital signatures, which are used to authenticate the sender of a message and ensure that the message has not been tampered with. This is done using RSA and DSA algorithms, which are widely used and respected in the industry.
Some Basic Cryptography...

Often, people make confusion between hashing and encryption, but encryption and hashing are two distinct concepts in cryptography. Encryption is a two-way process that transforms plaintext data into unreadable ciphertext to protect it from unauthorized access, and then transforms it back into plaintext when the authorized party needs to access it. On the other hand, hashing is a one-way process that takes plaintext data and transforms it into a fixed-length string of characters, known as a hash value or digest, that can't be reversed or transformed back into the original plaintext data, and is often used for data integrity, authenticity, and password storage purposes.
Hashing and Encryption

Hashing and encryption are two fundamental concepts in the field of cryptography. Hashing is a one-way process that transforms a variable-length input into a fixed-length string of characters, known as a hash value or digest. This transformation is irreversible, meaning that it is computationally infeasible to reverse engineer the hash value to obtain the original input.

Encryption is a two-way process that transforms plaintext data into unreadable ciphertext. This process is used to protect data from unauthorized access, ensuring confidentiality and security. Encryption involves using a cryptographic algorithm, such as AES or RSA, to transform the plaintext data into ciphertext. The ciphertext can only be deciphered with the decryption key.
Digital Signatures

A digital signature is a cryptographic mechanism that verifies the authenticity of a message or document. The process involves hashing the message and then encrypting the hash value with the sender's private key. The resulting encrypted hash value is attached to the message as a digital signature.
RSA Encryption

RSA encryption is a widely used public-key encryption algorithm. It involves generating a pair of keys, a public key and a private key. The public key is used to encrypt the data, while the private key is used to decrypt the data.
CBC Mode and GCM Mode

CBC (Cipher Block Chaining) mode and GCM (Galois/Counter Mode) mode are two commonly used modes of operation for block ciphers. CBC mode involves encrypting each block of plaintext data independently, while GCM mode involves encrypting the plaintext data in parallel.
Base64 and Hex Encoding/Decoding

Base64 and hex encoding/decoding are two common methods of encoding and decoding binary data. Base64 encoding involves converting binary data into a string of characters, while hex encoding involves converting binary data into a hexadecimal string.

### AES Encryption
For the AES (Advanced Encryption Standard), which is a widely used symmetric key algorithm, there are several modes of operation that can be used to provide various security properties, including confidentiality and authentication. Here are the most commonly used modes that are compatible with AES:


#### AES OpModes
- ECB (Electronic Codebook Mode):
Description: Each block of plaintext is encrypted independently. This mode is simple but not recommended for use in most applications due to its lack of security; identical plaintext blocks produce identical ciphertext blocks, which can reveal patterns. Use Case: Not recommended for secure applications.

- CBC (Cipher Block Chaining Mode):
Description: Each block of plaintext is XORed with the previous ciphertext block before being encrypted. This mode provides confidentiality but requires an initialization vector (IV) to ensure that identical plaintext blocks produce different ciphertext. Use Case: Commonly used for file encryption and secure communications.

- CFB (Cipher Feedback Mode):
Description: Converts a block cipher into a self-synchronizing stream cipher. It encrypts the previous ciphertext block and XORs it with the current plaintext block. Use Case: Useful for encrypting data streams.

- OFB (Output Feedback Mode):
Description: Similar to CFB, but it generates keystream blocks independently of the plaintext and ciphertext. It can be used to create a stream cipher from a block cipher. Use Case: Useful for applications where error propagation is a concern.

- CTR (Counter Mode):
Description: Converts a block cipher into a stream cipher by encrypting a counter value and XORing it with the plaintext. Each block uses a different counter value. Use Case: Highly efficient and allows for parallel processing. Suitable for high-speed applications.

- GCM (Galois/Counter Mode):
Description: Combines the counter mode of encryption with Galois mode of authentication. It provides both confidentiality and integrity/authentication. Use Case: Widely used in secure communications (e.g., TLS) and is recommended for applications requiring authenticated encryption.

- CCM (Counter with CBC-MAC):
Description: Combines counter mode encryption with CBC-MAC for authentication. It provides both confidentiality and integrity. Use Case: Suitable for applications requiring authenticated encryption, such as wireless communications.

- EAX (Encrypt-Then-Authenticate-Then-Transmit):
Description: An authenticated encryption mode that combines the features of CTR and CBC-MAC. It provides both confidentiality and integrity. Use Case: Useful for applications requiring authenticated encryption.

### For GOST and Serpent Algorithms

Possible Operation modes for GOST or Serpent:

- CBC (Cipher Block Chaining):
Provides confidentiality but does not provide authentication. You can combine it with a Message Authentication Code (MAC) like HMAC for integrity.

- CCM (Counter with CBC-MAC):
Provides both confidentiality and authentication. It is suitable for GOST and can be used for authenticated encryption.

- EAX:
Another mode that provides authenticated encryption. It can be used with GOST for both confidentiality and integrity.

- OFB (Output Feedback) or CFB (Cipher Feedback):
These modes can be used for streaming data but do not provide authentication.


### Security Considerations

It is essential to consider the security implications of using hashing and encryption. A secure hashing algorithm should be collision-resistant and pre-image resistant. A secure encryption algorithm should be resistant to known-plaintext attacks and chosen-ciphertext attacks.




### Class Structures

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

struct e_key_block_size {
    static const std::size_t
    AES = CryptoPP::AES::DEFAULT_KEYLENGTH,
    BLOWFISH = CryptoPP::Blowfish::DEFAULT_KEYLENGTH,
    CAST128 = CryptoPP::CAST128::DEFAULT_KEYLENGTH,
    CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH,
    IDEA = CryptoPP::IDEA::DEFAULT_KEYLENGTH,
    RC2 = CryptoPP::RC2::DEFAULT_KEYLENGTH,
    RC5 = CryptoPP::RC5::DEFAULT_KEYLENGTH,
    RC6 = CryptoPP::RC6::DEFAULT_KEYLENGTH,
    MARS = CryptoPP::MARS::DEFAULT_KEYLENGTH,
    SERPENT = CryptoPP::Serpent::DEFAULT_KEYLENGTH,
    GOST = CryptoPP::GOST::DEFAULT_KEYLENGTH;
};

struct e_iv_block_size {
    static const std::size_t
    AES = CryptoPP::AES::BLOCKSIZE,
    BLOWFISH = CryptoPP::Blowfish::BLOCKSIZE,
    CAST128 = CryptoPP::CAST128::BLOCKSIZE,
    CAST256 = CryptoPP::CAST256::BLOCKSIZE,
    IDEA = CryptoPP::IDEA::BLOCKSIZE,
    RC2 = CryptoPP::RC2::BLOCKSIZE,
    RC5 = CryptoPP::RC5::BLOCKSIZE,
    RC6 = CryptoPP::RC6::BLOCKSIZE,
    MARS = CryptoPP::MARS::BLOCKSIZE,
    SERPENT = CryptoPP::Serpent::BLOCKSIZE,
    GOST = CryptoPP::AES::BLOCKSIZE;
};
```

## Class Public Functions

**`hash`**

**`cbc_encrypt`**
**`cbc_decrypt`**

**`gcm_encrypt`**
**`gcm_decrypt`**

**`base64_encode`**
**`base64_decode`**

**`hex_encode`**
**`hex_decode`**

**`generate_rsa_key_der_pair`**

**`generate_rsa_key_pem_pair`**

**`sign_message`**

**`verify_signature`**

**`save_rsa_key`**

**`load_rsa_key`**



## Usage/Examples

### CBC Encryption

```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

/**
*  No template type specification, this will not work with GOST or Serpent algorithms.
**/
ByteCrypt bCrypt;

/**
* For GOST and Serpent algorithms...
**/
ByteCrypt<32, 16> byteCryptGost;

string buffer = "your mother"; // buffer to encrypt using "secret" key

string secret = "secret_key_for_decryption"; // this is the key used for encryption/decryption

string encrypted = bCrypt.cbc_encrypt(buffer, secret, e_symmetric_algo::AES); // encrypt buffer block and return result

std::cout << "encrypted: " << encrypted << "\n"; // print result

return 0;

}
```

### CBC Decryption

```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string decrypted = bCrypt.cbc_decrypt(encrypted, e_symmetric_algo::AES);

std::cout << "decrypted: " << decrypted << "\n";

return 0;

}
```

### GCM Encryption vs CBC Encryption


CBC (Cipher Block Chaining) and GCM (Galois/Counter Mode) are two modes of operation for symmetric-key block ciphers. In CBC, each block of plaintext is encrypted independently using the previous block's ciphertext as an initialization vector (IV). The IV is typically generated randomly and prepended to the ciphertext. While CBC is simple and efficient, it's vulnerable to certain attacks, such as block replay attacks and chosen-plaintext attacks.

GCM, on the other hand, combines a block cipher with a counter-based mode. Each block is encrypted using a block cipher, and a counter value is incremented for each block. The ciphertext is then authenticated using a Galois field (finite field) operation. This provides both confidentiality and integrity, as it authenticates the ciphertext and detects tampering. GCM is more secure than CBC due to its authentication mechanism, but it's also more computationally intensive.

the main difference between CBC and GCM is that GCM provides authentication, while CBC does not. This makes GCM a better choice for applications that require both confidentiality and integrity, such as secure communication protocols. In contrast, CBC may be sufficient for applications that only require confidentiality, such as data storage.

### GCM Encryption/Decryption example

```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

string encrypted = bCrypt.gcm_encrypt(buffer, secret, e_symmetric_algo::AES);

std::cout << "encrypted: " << encrypted << "\n";

string decrypted = bCrypt.gcm_decrypt(encrypted, e_symmetric_algo::AES);

std::cout << "decrypted: " << decrypted << "\n";

return 0;

}
```

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

string hashed = bCrypt.hash(buffer); // default hash with SHA256

std::cout << "Hashed: " << hashed << "\n"; // print result

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

string base64_encode = bCrypt.base64_encode(buffer);
string base64_decode = bCrypt.base64_decode(base64_encode);
string hex_encode = bCrypt.hex_encode(buffer);
string hex_decode = bCrypt.hex_decode(hex_encode); 

return 0;

}
```

### DER RSA Key Generation
> Generate a pair of RSA Keys(DER)
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(2048); 

// use keys...
const string public_key  = key_pair.public_key; 
const string private_key = key_pair.private_key; 

return 0;

}
```

### PEM RSA Key Generation
> Generate a pair of RSA Keys(PEM)
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){
const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_pem_pair(2048);

return 0;
}
```

### RSA Key Store/Load

> store or load RSA keys...
  
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

const rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_der_pair(3072);

const string public_key  = key_pair.public_key,  private_key = key_pair.private_key;

// --- Store ---
bCrypt.save_rsa_key("/home/user/Documents/RSA/priv.pem", key_pair.private_key.value()); 
bCrypt.save_rsa_key("/home/user/Documents/RSA/pub.pem", key_pair.public_key.value());

// --- Load ---
const rsa_key_block_load gpublic_key = bCrypt.load_rsa_key("/home/user/Documents/RSA/pub.pem");

return 0;
}
```

### Sign message
```cpp
int main(){
    
std::string signature = byte_crypt.sign_message(message, private_key);

if (signature.empty()) 
    return EXIT_FAILURE;
std::cout << "Signature: " << signature << std::endl;

return 0;
}
```

### Signature verification
```cpp
int main(){

bool is_verified = byte_crypt.verify_signature(message, signature, public_key);

if (is_verified) 
    std::cout << "Signature verification succeeded." << std::endl;
else 
    std::cerr << "Signature verification failed." << std::endl;


return 0;
}
```



### References

> "Hash Functions" by the National Institute of Standards and Technology (NIST)

> "Encryption" by the International Organization for Standardization (ISO)

> "Digital Signatures" by the Internet Engineering Task Force (IETF)
    
> "RSA Encryption" by the RSA Security Inc.
    
> "CBC Mode" by the National Institute of Standards and Technology (NIST)

> "GCM Mode" by the National Institute of Standards and Technology (NIST)

> "Base64 Encoding" by the Internet Engineering Task Force (IETF)
    
> "Hex Encoding" by the International Organization for Standardization (ISO)


## Useful links:

### Licenses
- [MIT License](https://github.com/Somorpher/ByteCrypt/blob/main/LICENSE)

### Acknowledgements
- [Symmetric Encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)
- [Asymmetric Encryption](https://en.wikipedia.org/wiki/Public-key_cryptography)
- [Block Cipher mode of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

### Crypto++ Library
- [Crypto++ website](https://cryptopp.com)

### Basic Cryptography Concepts
- [Hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [Encryption](https://en.wikipedia.org/wiki/Encryption)
- [Digital Signatures](https://en.wikipedia.org/wiki/Digital_signature)

### AES Encryption
- [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [ECB (Electronic Codebook Mode)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [CBC (Cipher Block Chaining Mode)](https://en.wikipedia.org/wiki/CBC-MAC)
- [CFB (Cipher Feedback Mode)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [CTR (Counter Mode)](https://www.includehelp.com/cryptography/counter-ctr-mode-in-cryptography.aspx)
- [GCM (Galois/Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [CCM (Counter with CBC-MAC)](https://en.wikipedia.org/wiki/CCM_mode)
- [EAX (Encrypt-Then-Authenticate-Then-Transmit)](https://en.wikipedia.org/wiki/EAX_mode)

### GOST and Serpent Ciphers
- [GOST](https://en.wikipedia.org/wiki/GOST_(block_cipher))
- [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))
