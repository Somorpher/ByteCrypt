# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          | Operation Mode  |
| ------- | ------------------ | --------------- |
| 0.0.1   | :white_check_mark: | CBC             |
| 0.0.1   | :white_check_mark: | GCM             |
| 0.0.1   | :white_check_mark: | EAX             |
| 0.0.1   | :white_check_mark: | CTR             |
| 0.0.1   | :white_check_mark: | CFB             |
| 0.0.1   | :white_check_mark: | OFB             |

    
| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 0.0.1   | :white_check_mark: | CBC             | AES         |
| 0.0.1   | :white_check_mark: | CBC             | BLOWFISH    |
| 0.0.1   | :white_check_mark: | CBC             | CAST128     |
| 0.0.1   | :white_check_mark: | CBC             | CAST256     |
| 0.0.1   | :white_check_mark: | CBC             | IDEA        |
| 0.0.1   | :white_check_mark: | CBC             | RC2         |
| 0.0.1   | :white_check_mark: | CBC             | RC5         |
| 0.0.1   | :white_check_mark: | CBC             | RC6         |
| 0.0.1   | :white_check_mark: | CBC             | MARS        |
| 0.0.1   | :white_check_mark: | CBC             | SERPENT     |
| 0.0.1   | :white_check_mark: | CBC             | GOST        |
| 0.0.1   | :white_check_mark: | CBC             | SPECK128    |
| 0.0.1   | :white_check_mark: | CBC             | SIMON       |
| 0.0.1   | :white_check_mark: | CBC             | HIGHT       |
| 0.0.1   | :white_check_mark: | CBC             | ARIA        |
| 0.0.1   | :x:                | CBC             | CHACHA      |
| 0.0.1   | :x:                | CBC             | TWOFISH     |
| 0.0.1   | :x:                | CBC             | SEAL        |

| Version | Supported          | Operation Mode  | Algorithm   |
| ------- | ------------------ | --------------- | ----------- |
| 0.0.1   | :white_check_mark: | CBC             | AES         |
| 0.0.1   | :x:                | CBC             | BLOWFISH    |
| 0.0.1   | :x:                | CBC             | CAST128     |
| 0.0.1   | :x:                | CBC             | CAST256     |
| 0.0.1   | :x:                | CBC             | IDEA        |
| 0.0.1   | :x:                | CBC             | RC2         |
| 0.0.1   | :x:                | CBC             | RC5         |
| 0.0.1   | :white_check_mark: | CBC             | RC6         |
| 0.0.1   | :white_check_mark: | CBC             | MARS        |
| 0.0.1   | :x:                | CBC             | SERPENT     |
| 0.0.1   | :x:                | CBC             | GOST        |
| 0.0.1   | :x:                | CBC             | SPECK128    |
| 0.0.1   | :x:                | CBC             | SIMON       |
| 0.0.1   | :x:                | CBC             | HIGHT       |
| 0.0.1   | :x:                | CBC             | ARIA        |
| 0.0.1   | :x:                | CBC             | CHACHA      |
| 0.0.1   | :x:                | CBC             | TWOFISH     |
| 0.0.1   | :x:                | CBC             | SEAL        |

## Reporting a Vulnerability
# Security Policy for ByteCrypt

## Reporting a Vulnerability

If you discover any security vulnerabilities within this project, please report them as soon as possible. We appreciate your help in improving the security of this project.

Please send a detailed email to [somorpher@proton.me](mailto:somorpher___@proton.me) with the following information:

- Description of the vulnerability
- Steps to reproduce the issue
- Environment details (operating system, compiler version, etc.)
- Any relevant code snippets

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


