# ByteCrypt

comprehensive cryptographic library that provides a range of cryptographic operations, including hashing using SHA1, SHA224, SHA256, SHA384, and SHA512 algorithms, encryption using AES and RSA algorithms, and digital signatures using RSA with SHA256 algorithm, along with key generation and verification functions, utilizing the Crypto++ library and designed to be highly flexible and easy to use for secure data storage, communication, and digital signatures.

### Introduction
Encryption Algorithm: AES (Advanced Encryption Standard)

The code uses the AES algorithm to encrypt and decrypt data. AES is a symmetric-key block cipher that is widely used for secure data transmission. 
It is a fast and efficient algorithm that can be used for both encryption and decryption.

### how the AES algorithm works:

* Key Generation: 
> generates a random key for encryption using the __derive_key_iv function. The key is derived from a password using a password-based key derivation function (PBKDF2).
   
* Encryption:
> uses the encrypt_block function to encrypt a block of data using the generated key. The encryption process involves the following steps:
1) Divide the data into blocks of 16 bytes (the block size of AES).
2) Apply a random initialization vector (IV) to the first block of data.
3) Encrypt each block of data using the AES algorithm with the generated key.
4) Store the encrypted data in a buffer.

* Decryption:
> uses the decrypt_block function to decrypt a block of encrypted data using the same key used for encryption. The decryption process involves the following steps:
1) Divide the encrypted data into blocks of 16 bytes.
2) Apply the random IV used during encryption to the first block of encrypted data.
3) Decrypt each block of encrypted data using the AES algorithm with the same key used for encryption.
4) Store the decrypted data in a buffer.

Hashing Algorithm: SHA (Secure Hash Algorithm)

uses the SHA algorithm to generate a digital fingerprint (hash) of data. SHA is a cryptographic hash function that is widely used for data integrity and authenticity.

Here's how the SHA algorithm works:

* Hash Calculation: 
uses the hash_block function to calculate the hash of a block of data using the SHA algorithm. The hash calculation involves the following steps:

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


### Implement Library

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

string hashed = bCrypt.hash_block(buffer); // default hash with SHA256

std::cout << "Hashed: " << hashed << "\n"; // print result

return 0;

}
```

### Encryption
> CBC mode encryption
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string buffer = "your mother"; // buffer to encrypt using "secret" key

string secret = "secret_key_for_decryption"; // this is the key used for encryption/decryption

string encrypted = bCrypt.encrypt_block(buffer, secret); // encrypt buffer block and return result

std::cout << "encrypted: " << encrypted << "\n"; // print result

return 0;

}
```

### Decryption
> CBC mode decryption
```cpp
#include "/path/to/ByteCrypt.hpp"

using namespace ByteCryptModule;

int main(){

ByteCrypt bCrypt;

string buffer = "your mother";

string secret = "secret_key_for_decryption";

string encrypted = bCrypt.encrypt_block(buffer, secret);

std::cout << "encrypted: " << encrypted << "\n";

string decrypted = bCrypt.decrypt_block(encrypted, secret);

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
