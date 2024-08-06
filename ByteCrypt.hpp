#pragma once

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory.h>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <time.h>
#include <typeinfo>
#include <unistd.h>
#include <filesystem>
#include <bitset>
#include <unordered_set>

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
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

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__ 1

namespace ByteCryptModule
{

    /*                      Type Alias                       *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    using byte = CryptoPP::byte;

    /*                      Macros                           *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

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
    using string_t = std::basic_string<char>;
    using string_view_t = std::basic_string_view<char>;
    using cbc_cipher_t = CryptoPP::Rijndael;
    using cbc_aes_encryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Encryption;
    using cbc_aes_decryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Decryption;

    class ByteCrypt
    {

        const std::uint16_t cipher_iteration_count = 10000;
        const std::uint8_t default_sec_key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
        const std::uint8_t default_sec_iv_size = CryptoPP::AES::BLOCKSIZE;

        byte __key__[CryptoPP::AES::DEFAULT_KEYLENGTH];
        byte __iv__[CryptoPP::AES::BLOCKSIZE];

    public:
        ByteCrypt() {};

        const string_t hash_block(const string_t& buffer, const e_hash_algo_option sha = e_hash_algo_option::SHA256)
        {
            string_t digest_block;
            if (sha == e_hash_algo_option::SHA1)
            {
                CryptoPP::SHA1 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == e_hash_algo_option::SHA224)
            {
                CryptoPP::SHA224 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == e_hash_algo_option::SHA256)
            {
                CryptoPP::SHA256 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == e_hash_algo_option::SHA384)
            {
                CryptoPP::SHA384 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == e_hash_algo_option::SHA512)
            {
                CryptoPP::SHA512 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == e_hash_algo_option::SHA384)
            {
                CryptoPP::SHA384 algo;
                CryptoPP::StringSource dig_source(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            return digest_block;
        };

        const string_t encrypt_block(const string_t& plain_text, const string_t &key)
        {
            string_t cipher, encoded_cipher;
            try
            {
                this->__derive_key_iv(key, this->__key__, this->__iv__);
                cbc_aes_encryption_t aes_encryption;
                this->__perform_keyiv_collision(aes_encryption);
                CryptoPP::StringSource(plain_text, true, new CryptoPP::StreamTransformationFilter(aes_encryption, new CryptoPP::StringSink(cipher)));
                CryptoPP::StringSource(cipher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded_cipher)));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Encrypt Error: " << e.what() << "\n";
            }
            return encoded_cipher;
        };

        const string_t decrypt_block(const string_t& cipher_block, const string_t& u_key)
        {
            string_t decrypted_cipher, decoded_cipher;
            try
            {
                cbc_aes_decryption_t aes_decryption;
                this->__perform_keyiv_collision(aes_decryption);
                CryptoPP::StringSource(cipher_block, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded_cipher)));
                CryptoPP::StringSource(decoded_cipher, true, new CryptoPP::StreamTransformationFilter(aes_decryption, new CryptoPP::StringSink(decrypted_cipher)));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Decryption Error: " << e.what() << "\n";
            }
            return decrypted_cipher;
        };

        inline const string_t base64_encode(const string_t& plain_text)
        {
            string_t b64_encoded;
            CryptoPP::StringSource(plain_text, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(b64_encoded)));
            return b64_encoded;
        };

        inline const string_t base64_decode(const string_t& encoded_cipher) {
            string_t b64_decoded;
            CryptoPP::StringSource(encoded_cipher, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(b64_decoded)));
            return b64_decoded;
        };

        inline const string_t hex_encode(const string_t& plain_text) noexcept {
            std::ostringstream parser;
            for(unsigned char _byte: plain_text)
                parser << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_byte);
            return parser.str();
        };

        inline const string_t hex_decode(const string_t& hex_encoded) {
            if(hex_encoded.length() % 2 != 0)
                throw std::invalid_argument("hex encoded buffer length error!");
            string_t hex_decoded;
            hex_decoded.reserve(hex_encoded.length() / 2);
            for(std::size_t _i{0}; _i < hex_encoded.length(); _i += 2){
                string_t byte_code(hex_encoded.substr(_i, 2));
                char byte_char = static_cast<char>(std::stoi(byte_code, nullptr, 16));
                hex_decoded.push_back(byte_char);
            }
            return hex_decoded;
        };


        ~ByteCrypt() {};

    private:
        void __derive_key_iv(const string_t &u_pwd, byte *key, byte *init_vector)
        {
            byte salt[16];
            CryptoPP::AutoSeededRandomPool PRNG;
            PRNG.GenerateBlock(salt, sizeof(salt));
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> transformer;
            transformer.DeriveKey(key, default_sec_key_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
            transformer.DeriveKey(init_vector, default_sec_iv_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
        };

        inline void __perform_keyiv_collision(cbc_aes_encryption_t &encryption_handler) noexcept
        {
            encryption_handler.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
        };
        inline void __perform_keyiv_collision(cbc_aes_decryption_t &decryption_handler) noexcept
        {
            decryption_handler.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
        };
    };
};

#endif
