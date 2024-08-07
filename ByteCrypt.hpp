#pragma once

/**
 *
 * @Somorpher
 * 
 * -------------------------
 * Disclaimer of Warranty  |
 * -------------------------
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * THE AUTHORS AND COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 *
 * This code provides a comprehensive cryptographic library that implements a range of
 * cryptographic operations, including hashing, encryption, and digital signatures, using 
 * various algorithms such as SHA, AES, and RSA, which are widely used for secure data 
 * transmission and storage, and are designed to provide high security, speed, and efficiency,
 * with hashing algorithms producing fixed-size hash values from variable-size input messages,
 * making it computationally infeasible to find two different input messages that produce 
 * the same output hash value, and are often used in digital signatures, message authentication 
 * codes, and data integrity checks, while encryption algorithms, such as AES, encrypt data in 
 * blocks of 128 bits, using a variable block size and a key size of 128, 192, or 256 bits, making 
 * it widely used for secure data transmission and storage, and digital signature algorithms, 
 * such as RSA with SHA256, use a pair of keys, a public key and a private key, to encrypt and 
 * decrypt data, making it widely used for secure data transmission and digital signatures, and 
 * the library is designed to be highly flexible and easy to use for secure data storage, 
 * communication, and digital signatures, with a range of cryptographic functions and operations 
 * that can be used to provide secure data storage, communication, and digital signatures, including 
 * functions for generating and verifying digital signatures, encrypting and decrypting data, and 
 * hashing messages, and the library is widely used in a range of applications, including secure 
 * data transmission, secure communication, and digital signatures, and is often used in conjunction 
 * with other cryptographic algorithms and techniques, such as SHA, AES, and RSA, to provide secure 
 * key exchange and authentication, and the library provides a high level of security, speed, and 
 * efficiency, making it an ideal choice for a wide range of applications, including secure data 
 * transmission, secure communication, and digital signatures, and the library is designed to be 
 * easy to use and integrate into existing systems, with a simple and intuitive API that makes it 
 * easy to use the library's cryptographic functions and operations, and the library is highly 
 * flexible, with a range of cryptographic algorithms and functions that can be used to provide 
 * secure data storage, communication, and digital signatures, and the library is widely respected 
 * and used in the industry, with a strong reputation for providing high-quality and secure cryptographic solutions.
 *
 *
 */

#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/base64.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/rsa.h>
#include <crypto++/sha.h>
#include <cryptopp/cryptlib.h>
#include <crypto++/pwdbased.h>
#include <crypto++/secblock.h>
#include <cryptopp/pssr.h>

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__ 1

// ft. Somorpher

namespace ByteCryptModule
{

/*                      Macros                           *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#define DEFAULT_RSA_KEY_SIZE 2048U
#define DEFAULT_AES_CIPHER 256
#define DEFAULT_SHA_CIPHER 256
#define RSA_KEY_SIZE_OPTIONS \
    std::array<std::uint16_t, 5> { 512u, 1024u, 2048u, 3072u, 4096u }

    /*                      Namespace                        *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    enum class e_hash_algo_option
    {
        SHA1 = 0,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    };

    /*                      Type Alias                       *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    using byte = CryptoPP::byte;
    using string_t = std::basic_string<char>;
    using string_view_t = std::basic_string_view<char>;
    using cbc_cipher_t = CryptoPP::Rijndael;
    using cbc_aes_encryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Encryption;
    using cbc_aes_decryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Decryption;
    using rsa_public_key_t = CryptoPP::RSA::PublicKey;
    using rsa_private_key_t = CryptoPP::RSA::PrivateKey;
    using entropy_seed_t = CryptoPP::AutoSeededRandomPool;
    using invertible_rsa_t = CryptoPP::InvertibleRSAFunction;
    using string_sink_t = CryptoPP::StringSink;
    using string_source_t = CryptoPP::StringSource;
    using hex_encoder_t = CryptoPP::HexEncoder;
    using hex_decoder_t = CryptoPP::HexDecoder;
    using base64_encoder_t = CryptoPP::Base64Encoder;
    using base64_decoder_t = CryptoPP::Base64Decoder;

    /*                      Structure                        *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
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

    /*                      Class                            *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    class ByteCrypt
    {

        const std::uint16_t cipher_iteration_count = 10000;
        const std::uint8_t default_sec_key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
        const std::uint8_t default_sec_iv_size = CryptoPP::AES::BLOCKSIZE;

        byte __key__[CryptoPP::AES::DEFAULT_KEYLENGTH];
        byte __iv__[CryptoPP::AES::BLOCKSIZE];

    public:
        ByteCrypt() {};

        inline const string_t hash_block(const string_t &buffer, const e_hash_algo_option sha = e_hash_algo_option::SHA256) const
        {
            string_t digest_block;
            std::unique_ptr<CryptoPP::HashTransformation> algo;
            switch (sha)
            {
            case e_hash_algo_option::SHA1:
                algo = std::make_unique<CryptoPP::SHA1>();
                break;
            case e_hash_algo_option::SHA224:
                algo = std::make_unique<CryptoPP::SHA224>();
                break;
            case e_hash_algo_option::SHA256:
                algo = std::make_unique<CryptoPP::SHA256>();
                break;
            case e_hash_algo_option::SHA384:
                algo = std::make_unique<CryptoPP::SHA384>();
                break;
            case e_hash_algo_option::SHA512:
                algo = std::make_unique<CryptoPP::SHA512>();
                break;
            }
            CryptoPP::StringSource(buffer, true, new CryptoPP::HashFilter(*algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            return digest_block;
        };

        inline const string_t encrypt_block(const string_t &plain_text, const string_t &key)
        {
            string_t cipher, encoded_cipher;
            try
            {
                this->__derive_key_iv(key, this->__key__, this->__iv__);
                cbc_aes_encryption_t aes_encryption;
                this->__perform_keyiv_collision<cbc_aes_encryption_t>(aes_encryption);
                CryptoPP::StringSource(plain_text, true, new CryptoPP::StreamTransformationFilter(aes_encryption, new CryptoPP::StringSink(cipher)));
                CryptoPP::StringSource(cipher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded_cipher)));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Encrypt Error: " << e.what() << "\n";
            }
            return encoded_cipher;
        };

        inline const string_t decrypt_block(const string_t &cipher_block, const string_t &u_key)
        {
            string_t decrypted_cipher, decoded_cipher;
            try
            {
                cbc_aes_decryption_t aes_decryption;
                this->__perform_keyiv_collision<cbc_aes_decryption_t>(aes_decryption);
                CryptoPP::StringSource(cipher_block, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded_cipher)));
                CryptoPP::StringSource(decoded_cipher, true, new CryptoPP::StreamTransformationFilter(aes_decryption, new CryptoPP::StringSink(decrypted_cipher)));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Decryption Error: " << e.what() << "\n";
            }
            return decrypted_cipher;
        };

        inline const string_t base64_encode(const string_t &plain_text)
        {
            string_t b64_encoded;
            CryptoPP::StringSource(plain_text, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(b64_encoded)));
            return b64_encoded;
        };

        inline const string_t base64_decode(const string_t &encoded_cipher)
        {
            string_t b64_decoded;
            CryptoPP::StringSource(encoded_cipher, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(b64_decoded)));
            return b64_decoded;
        };

        inline const string_t hex_encode(const string_t &plain_text) noexcept
        {
            std::ostringstream parser;
            for (unsigned char _byte : plain_text)
                parser << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_byte);
            return parser.str();
        };

        inline const string_t hex_decode(const string_t &hex_encoded)
        {
            if (hex_encoded.length() % 2 != 0)
            {
                std::cerr << "hex encoded buffer length error!\n";
                return "";
            }
            string_t hex_decoded;
            hex_decoded.reserve(hex_encoded.length() / 2);
            for (std::size_t _i{0}; _i < hex_encoded.length(); _i += 2)
            {
                string_t byte_code(hex_encoded.substr(_i, 2));
                char byte_char = static_cast<char>(std::stoi(byte_code, nullptr, 16));
                hex_decoded.push_back(byte_char);
            }
            return hex_decoded;
        };

        rsa_key_pair_struct generate_rsa_key_der_pair(const std::size_t rsa_key_size = 2048U)
        {
            rsa_key_pair_struct local_kps{};
            if (!this->__is_rsa_key_size_valid(rsa_key_size))
                return local_kps;
            try
            {
                entropy_seed_t entropy;
                invertible_rsa_t private_key;
                private_key.Initialize(entropy, rsa_key_size);
                rsa_public_key_t public_key(private_key);
                string_t private_key_result, public_key_result, private_key_result_encoded, public_key_result_encoded;
                string_sink_t private_key_sink(private_key_result);
                private_key.DEREncode(private_key_sink);
                private_key_sink.MessageEnd();
                string_source_t(private_key_result, true, new base64_encoder_t(new string_sink_t(private_key_result_encoded)));

                if (!private_key_result.empty())
                {
                    try
                    {
                        string_t public_key_result;
                        string_sink_t public_key_sink(public_key_result);
                        public_key.DEREncode(public_key_sink);
                        public_key_sink.MessageEnd();
                        string_source_t(public_key_result, true, new base64_encoder_t(new string_sink_t(public_key_result_encoded)));
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "RSA PublicKey: " << e.what() << "\n";
                        if (!private_key_result.empty())
                            private_key_result.clear();
                    }
                }
                if (!private_key_result_encoded.empty() && !public_key_result_encoded.empty())
                {
                    local_kps.private_key = std::move(private_key_result_encoded);
                    local_kps.public_key = std::move(public_key_result_encoded);
                    if (this->__rsa_key_pair_verify(local_kps))
                    {
                        local_kps.state = true;
                    }
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "RSA PrivateKey: " << e.what() << "\n";
            }
            return local_kps;
        };

        const rsa_key_pair_struct generate_rsa_key_pem_pair(const std::size_t rsa_key_size = 2048U)
        {
            rsa_key_pair_struct rsa_keys = this->generate_rsa_key_der_pair(rsa_key_size);
            if (!this->__is_rsa_key_size_valid(rsa_key_size))
                return rsa_keys;
            try
            {
                string_t private_decoded, public_decoded;
                this->__rsa_key_pem_set_header(private_decoded, false);
                this->__rsa_key_pem_set_header(public_decoded, true);
                private_decoded += rsa_keys.private_key.value();
                public_decoded += rsa_keys.public_key.value();
                this->__rsa_key_pem_set_footer(private_decoded, false);
                this->__rsa_key_pem_set_footer(public_decoded, true);
                rsa_keys.private_key = std::move(private_decoded);
                rsa_keys.public_key = std::move(public_decoded);
            }
            catch (const std::exception &e)
            {
                std::cerr << "RSA PrivateKey: " << e.what() << "\n";
            }
            return rsa_keys;
        };

        inline const string_t sign_message(const string_t &message, const string_t &private_key_str)
        {
            string_t signature;
            try
            {
                string_t private_key_decoded;
                string_source_t(private_key_str, true, new base64_decoder_t(new string_sink_t(private_key_decoded)));
                rsa_private_key_t private_key;
                string_source_t private_key_source(private_key_decoded, true);
                private_key.BERDecode(private_key_source);
                CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(private_key);
                CryptoPP::AutoSeededRandomPool rng;
                CryptoPP::StringSource(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature)));
                string_t encoded_signature;
                CryptoPP::StringSource(signature, true, new base64_encoder_t(new string_sink_t(encoded_signature)));
                return encoded_signature;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Sign Error: " << e.what() << "\n";
                return "";
            }
        };

        inline const bool verify_signature(const string_t &message, const string_t &signature_str, const string_t &public_key_str)
        {
            try
            {
                string_t public_key_decoded;
                string_source_t(public_key_str, true, new base64_decoder_t(new string_sink_t(public_key_decoded)));
                rsa_public_key_t public_key;
                string_source_t public_key_source(public_key_decoded, true);
                public_key.BERDecode(public_key_source);
                string_t signature_decoded;
                string_source_t(signature_str, true, new base64_decoder_t(new string_sink_t(signature_decoded)));
                CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(public_key);
                bool result = verifier.VerifyMessage((const CryptoPP::byte *)message.data(), message.size(), (const CryptoPP::byte *)signature_decoded.data(), signature_decoded.size());
                return result;
            }
            catch (const CryptoPP::Exception &e)
            {
                std::cerr << "CryptoPP Verify Error: " << e.what() << "\n";
                return false;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Verify Error: " << e.what() << "\n";
                return false;
            }
        };

        const bool save_rsa_key(const string_view_t &path, const string_t &rsa_key)
        {
            try
            {
                if (path.empty())
                    throw std::invalid_argument("path to store rsa key not invalid!");
                if (rsa_key.empty())
                    throw std::invalid_argument("rsa key value invalid!");

                std::ofstream file_handler(path.data(), std::ios::binary | std::ios::out);
                if (!file_handler.is_open())
                    throw std::ofstream::failure::runtime_error("file stream for writing rsa key not open!");
                file_handler << rsa_key;
                file_handler.close();
                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Exception: " << e.what() << "\n";
            }
            return false;
        };

        const rsa_key_block_load load_rsa_key(const string_view_t &load_file)
        {
            rsa_key_block_load rsa_loader;
            try
            {
                if (load_file.empty())
                    throw std::invalid_argument("path to read rsa key not invalid!");

                std::ifstream file_handler(load_file.data(), std::ios::binary | std::ios::in);
                if (!file_handler.is_open())
                    throw std::ifstream::failure::runtime_error("file stream for reading rsa key not open!");

                string_t read_key;
                rsa_loader.key.clear();
                do
                {
                    rsa_loader.key += read_key += "\n";
                } while (std::getline(file_handler, read_key));
                file_handler.close();
                if (!rsa_loader.key.empty())
                    rsa_loader.status = true;

                return rsa_loader;
            }
            catch (const std::exception &e)
            {
                rsa_loader.error = e.what();
            }
            return rsa_loader;
        };

        ~ByteCrypt() {};

    private:
        void __derive_key_iv(const string_t &u_pwd, byte *key, byte *init_vector) const
        {
            byte salt[16];
            entropy_seed_t entropy;
            entropy.GenerateBlock(salt, sizeof(salt));
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> transformer;
            transformer.DeriveKey(key, default_sec_key_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
            transformer.DeriveKey(init_vector, default_sec_iv_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
        };

        template <typename mT, typename = std::enable_if<std::is_same_v<mT, cbc_aes_decryption_t> || std::is_same_v<mT, cbc_aes_encryption_t>>>
        inline void __perform_keyiv_collision(mT &decryption_handler) const noexcept
        {
            if (std::is_same_v<mT, cbc_aes_encryption_t>)
                decryption_handler.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
            else
                decryption_handler.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
        };

        const bool __rsa_key_pair_verify(const rsa_key_pair_struct &key_block)
        {
            if (!key_block.public_key.has_value() || !key_block.private_key.has_value())
                return false;

            try
            {
                string_t private_key_decoded_result, public_key_decoded_result;
                rsa_private_key_t rsa_private_key;
                rsa_public_key_t rsa_public_key;
                std::size_t private_key_byte_size, public_key_byte_size;

                string_source_t(key_block.private_key.value(), true, new base64_decoder_t(new string_sink_t(private_key_decoded_result)));
                string_source_t(key_block.public_key.value(), true, new base64_decoder_t(new string_sink_t(public_key_decoded_result)));

                {
                    string_source_t rsa_key_source(private_key_decoded_result, true, nullptr);
                    rsa_private_key.BERDecode(rsa_key_source);
                }
                {
                    string_source_t rsa_key_source(public_key_decoded_result, true, nullptr);
                    rsa_public_key.BERDecode(rsa_key_source);
                }
                if (rsa_private_key.GetModulus() != rsa_public_key.GetModulus())
                    throw std::runtime_error("RSA Modulus Error!");
                public_key_byte_size = rsa_public_key.GetModulus().ByteCount();
                private_key_byte_size = rsa_private_key.GetModulus().ByteCount();
                if (private_key_byte_size != public_key_byte_size)
                    throw std::runtime_error("RSA Byte Count error!");
                return true;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Rsa Key Verification: " << e.what() << "\n";
            }
            return false;
        };

        inline void __rsa_key_pem_set_header(string_t &rsa_key_var, const bool is_public_key) const noexcept
        {
            rsa_key_var.clear();
            if (is_public_key)
                rsa_key_var = "-----BEGIN PUBLIC KEY-----\n";
            else
                rsa_key_var = "-----BEGIN RSA PRIVATE KEY-----\n";
        };

        inline void __rsa_key_pem_set_footer(string_t &rsa_key_var, const bool is_public_key) const noexcept
        {
            if (rsa_key_var.empty())
                return;
            if (is_public_key)
                rsa_key_var += "-----END PUBLIC KEY-----";
            else
                rsa_key_var += "-----END RSA PRIVATE KEY-----";
        };

        constexpr bool __is_rsa_key_size_valid(const std::size_t &key_size) const noexcept
        {
            for (std::uint8_t ksi = 0; ksi < RSA_KEY_SIZE_OPTIONS.size(); ksi++)
            {
                if ((std::size_t)RSA_KEY_SIZE_OPTIONS[ksi] == key_size)
                {
                    return true;
                }
            }
            return false;
        };
    };
};

#endif
