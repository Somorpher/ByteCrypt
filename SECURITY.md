# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

### Mode Of Operation Supported

| Version | Supported          | Operation Mode  |
| ------- | ------------------ | --------------- |
| 1.0.0   | :white_check_mark: | CBC             |
| 1.0.0   | :white_check_mark: | GCM             |
| 1.0.0   | :white_check_mark: | EAX             |
| 1.0.0   | :white_check_mark: | CTR             |
| 1.0.0   | :white_check_mark: | CFB             |
| 1.0.0   | :white_check_mark: | OFB             |

### CBC Mode Algorithm Support
    
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | CBC             | AES         |
| 1.0.0   | :white_check_mark: | CBC             | BLOWFISH    |
| 1.0.0   | :white_check_mark: | CBC             | CAST128     |
| 1.0.0   | :white_check_mark: | CBC             | CAST256     |
| 1.0.0   | :white_check_mark: | CBC             | IDEA        |
| 1.0.0   | :white_check_mark: | CBC             | RC2         |
| 1.0.0   | :white_check_mark: | CBC             | RC5         |
| 1.0.0   | :white_check_mark: | CBC             | RC6         |
| 1.0.0   | :white_check_mark: | CBC             | MARS        |
| 1.0.0   | :white_check_mark: | CBC             | SERPENT     |
| 1.0.0   | :white_check_mark: | CBC             | GOST        |
| 1.0.0   | :white_check_mark: | CBC             | SPECK128    |
| 1.0.0   | :white_check_mark: | CBC             | SIMON       |
| 1.0.0   | :white_check_mark: | CBC             | HIGHT       |
| 1.0.0   | :white_check_mark: | CBC             | ARIA        |
| 1.0.0   | :x:                | CBC             | CHACHA      |
| 1.0.0   | :x:                | CBC             | TWOFISH     |
| 1.0.0   | :x:                | CBC             | SEAL        |

### EAX Mode Algorithm Support

| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | EAX             | AES         |
| 1.0.0   | :white_check_mark: | EAX             | BLOWFISH    |
| 1.0.0   | :white_check_mark: | EAX             | CAST128     |
| 1.0.0   | :white_check_mark: | EAX             | CAST256     |
| 1.0.0   | :white_check_mark: | EAX             | IDEA        |
| 1.0.0   | :x:                | EAX             | RC2         |
| 1.0.0   | :white_check_mark: | EAX             | RC5         |
| 1.0.0   | :white_check_mark: | EAX             | RC6         |
| 1.0.0   | :white_check_mark: | EAX             | MARS        |
| 1.0.0   | :white_check_mark: | EAX             | SERPENT     |
| 1.0.0   | :white_check_mark: | EAX             | GOST        |
| 1.0.0   | :white_check_mark: | EAX             | SPECK128    |
| 1.0.0   | :white_check_mark: | EAX             | SIMON       |
| 1.0.0   | :white_check_mark: | EAX             | HIGHT       |
| 1.0.0   | :x:                | EAX             | ARIA        |
| 1.0.0   | :x:                | EAX             | CHACHA      |
| 1.0.0   | :x:                | EAX             | TWOFISH     |
| 1.0.0   | :x:                | EAX             | SEAL        |

### GCM Mode Algorithm Support
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | GCM             | AES         |
| 1.0.0   | :x:                | GCM             | BLOWFISH    |
| 1.0.0   | :x:                | GCM             | CAST128     |
| 1.0.0   | :x:                | GCM             | CAST256     |
| 1.0.0   | :x:                | GCM             | IDEA        |
| 1.0.0   | :x:                | GCM             | RC2         |
| 1.0.0   | :x:                | GCM             | RC5         |
| 1.0.0   | :white_check_mark: | GCM             | RC6         |
| 1.0.0   | :white_check_mark: | GCM             | MARS        |
| 1.0.0   | :x:                | GCM             | SERPENT     |
| 1.0.0   | :x:                | GCM             | GOST        |
| 1.0.0   | :x:                | GCM             | SPECK128    |
| 1.0.0   | :x:                | GCM             | SIMON       |
| 1.0.0   | :x:                | GCM             | HIGHT       |
| 1.0.0   | :x:                | GCM             | ARIA        |
| 1.0.0   | :x:                | GCM             | CHACHA      |
| 1.0.0   | :white_check_mark: | GCM             | TWOFISH     |
| 1.0.0   | :x:                | GCM             | SEAL        |

### CFB Mode Algorithm Support
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | CFB             | AES         |
| 1.0.0   | :white_check_mark: | CFB             | BLOWFISH    |
| 1.0.0   | :white_check_mark: | CFB             | CAST128     |
| 1.0.0   | :white_check_mark: | CFB             | CAST256     |
| 1.0.0   | :white_check_mark: | CFB             | IDEA        |
| 1.0.0   | :white_check_mark: | CFB             | RC2         |
| 1.0.0   | :white_check_mark: | CFB             | RC5         |
| 1.0.0   | :x:                | CFB             | RC6         |
| 1.0.0   | :x:                | CFB             | MARS        |
| 1.0.0   | :x:                | CFB             | SERPENT     |
| 1.0.0   | :x:                | CFB             | GOST        |
| 1.0.0   | :x:                | CFB             | SPECK128    |
| 1.0.0   | :x:                | CFB             | SIMON       |
| 1.0.0   | :x:                | CFB             | HIGHT       |
| 1.0.0   | :x:                | CFB             | ARIA        |
| 1.0.0   | :x:                | CFB             | CHACHA      |
| 1.0.0   | :white_check_mark: | CFB             | TWOFISH     |
| 1.0.0   | :x:                | CFB             | SEAL        |


### OFB Mode Algorithm Support
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | OFB             | AES         |
| 1.0.0   | :white_check_mark: | OFB             | BLOWFISH    |
| 1.0.0   | :white_check_mark: | OFB             | CAST128     |
| 1.0.0   | :white_check_mark: | OFB             | CAST256     |
| 1.0.0   | :white_check_mark: | OFB             | IDEA        |
| 1.0.0   | :white_check_mark: | OFB             | RC2         |
| 1.0.0   | :white_check_mark: | OFB             | RC5         |
| 1.0.0   | :x:                | OFB             | RC6         |
| 1.0.0   | :x:                | OFB             | MARS        |
| 1.0.0   | :x:                | OFB             | SERPENT     |
| 1.0.0   | :x:                | OFB             | GOST        |
| 1.0.0   | :x:                | OFB             | SPECK128    |
| 1.0.0   | :x:                | OFB             | SIMON       |
| 1.0.0   | :x:                | OFB             | HIGHT       |
| 1.0.0   | :x:                | OFB             | ARIA        |
| 1.0.0   | :x:                | OFB             | CHACHA      |
| 1.0.0   | :white_check_mark: | OFB             | TWOFISH     |
| 1.0.0   | :x:                | OFB             | SEAL        |


### CTR Mode Algorithm Support
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 1.0.0   | :white_check_mark: | CTR             | AES         |
| 1.0.0   | :white_check_mark: | CTR             | BLOWFISH    |
| 1.0.0   | :white_check_mark: | CTR             | CAST128     |
| 1.0.0   | :white_check_mark: | CTR             | CAST256     |
| 1.0.0   | :white_check_mark: | CTR             | IDEA        |
| 1.0.0   | :white_check_mark: | CTR             | RC2         |
| 1.0.0   | :white_check_mark: | CTR             | RC5         |
| 1.0.0   | :x:                | CTR             | RC6         |
| 1.0.0   | :x:                | CTR             | MARS        |
| 1.0.0   | :x:                | CTR             | SERPENT     |
| 1.0.0   | :x:                | CTR             | GOST        |
| 1.0.0   | :x:                | CTR             | SPECK128    |
| 1.0.0   | :x:                | CTR             | SIMON       |
| 1.0.0   | :x:                | CTR             | HIGHT       |
| 1.0.0   | :x:                | CTR             | ARIA        |
| 1.0.0   | :x:                | CTR             | CHACHA      |
| 1.0.0   | :white_check_mark: | CTR             | TWOFISH     |
| 1.0.0   | :x:                | CTR             | SEAL        |

## Reporting a Vulnerability
# Security Policy for ByteCrypt

## Reporting a Vulnerability

If you discover any security vulnerabilities within this project, please report them as soon as possible. We appreciate your help in improving the security of this project.

## Security Practices

### Cryptographic Best Practices

1. **Use Strong Keys**: Always use recommended key sizes when generating keys (2048 bits for RSA keys is recommended).
2. **Initialization Vectors (IV)**: Ensure that the initialization vector used in encryption modes is generated securely and is unique for each encryption operation.
3. **Do Not Reuse Keys**: Avoid reusing cryptographic keys across different encryption sessions. Each session should use a newly generated key where applicable.
4. **Secret Management**: Secrets (keys, IVs) should be stored securely. Avoid hardcoding secrets in your code. Use secure storage solutions when relevant.

### Algorithms and Modes

- This library supports various symmetric and asymmetric encryption algorithms and modes. Be sure to select appropriate encryption modes for your use case (e.g., GCM for authenticated encryption).
- Avoid using outdated or weak algorithms (e.g., MD5 hashing) wherever possible. Prefer stronger hashing functions like SHA-256 or bcrypt for password hashing.

### Exception Handling

Make use of the built-in error handling mechanisms to manage exceptions gracefully during cryptographic operations. Avoid revealing sensitive information in error messages.

### Dependencies

Ensure that the project's dependencies (like Crypto++) are regularly updated to their latest stable versions to mitigate known vulnerabilities.

## Security Audit

This project will undergo regular security audits. Contributions that introduce new functionality must also include a review of potential security implications.

## License

This project is licensed under the MIT License. Security clauses from the license apply to any contributions or usage of the project.


