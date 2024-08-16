#pragma once

/**
 * ============================================================================
 * ByteCrypt Class - A C++ Data Encryption Utility Module
 * ============================================================================
 *
 * MIT License
 *
 * Copyright (c) 2024 Somorpher
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ============================================================================
 *
 * Written by [Somorpher], [2024].
 */

/**
 * Cryptographic Utility library for most common cryptograpic operations, algorithms, modes, etc...
 *
 * Symmetric Cryptography:
 * Available Modes: CBC((16+-)algos), GCM((4+-)algos), EAX((15+-)algos), CFB((6+-)algos), OFB((7+-)algos), CTR((6+-)algos)
 * Hashing: SHA1, SHA224, SHA256, SHA384, SHA512, Tiger, Whirlpool, MD5, Blake2, Ripemd160
 * Encoding: base64, hex
 *
 * Asymmetric Cryptography:
 * RSA
 * Message Signing, message authentication, Signature generation/verification, RSA key generation(DER, PEM) with
 * different key size available(512, 1024, 2048, 3072, 4096), etc...
 *
 */

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32) || defined(_WIN64) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) ||       \
    defined(__sun) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(__ANDROID__) || defined(__unix__) || defined(__HAIKU__)

#if defined(__x86_64__) || defined(__amd64__) || defined(__aarch64__) || defined(__mips64__) || defined(__s390x__) || defined(__riscv64__)

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__) || defined(_MSC_VER)

#if defined(_WIN32) || defined(_WIN64)
#define PATH_SEPARATOR "\\"
#include <windows.h>
#else
#define PATH_SEPARATOR "/" // not about this as well, it should be inferred by the compiler ...
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/aria.h>
#include <crypto++/base64.h>
#include <crypto++/blowfish.h>
#include <crypto++/cast.h>
#include <crypto++/chacha.h>
#include <crypto++/eax.h>
#include <crypto++/filters.h>
#include <crypto++/gcm.h>
#include <crypto++/gost.h>
#include <crypto++/hex.h>
#include <crypto++/hight.h>
#include <crypto++/idea.h>
#include <crypto++/lea.h>
#include <crypto++/mars.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/pwdbased.h>
#include <crypto++/rc2.h>
#include <crypto++/rc5.h>
#include <crypto++/rc6.h>
#include <crypto++/rijndael.h>
#include <crypto++/secblock.h>
#include <crypto++/seed.h>
#include <crypto++/serpent.h>
#include <crypto++/sha.h>
#include <crypto++/simon.h>
#include <crypto++/speck.h>
#include <crypto++/twofish.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/pssr.h>

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__

/**
 * Utility within namespace to avoid namespace pollution.
 */
namespace ByteCryptModule
{

/*                      Macros                           *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#define DEFAULT_CIPHER_ITERATION_COUNTER 10000
#define DEFAULT_SEC_BLOCK_KEY_SIZE CryptoPP::AES::DEFAULT_KEYLENGTH
#define DEFAULT_SEC_BLOCK_IV_SIZE CryptoPP::AES::BLOCKSIZE


/*                      Attribution                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)

#define __hint_set_iter_counter__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_set_def_key_size__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_set_def_iv_size__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_prepare_secure_keys__ __attribute__((stack_protect, zero_call_used_regs("used"), optimize("3")))
#define __hint_cipher_transformation__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), noinline, access(read_only, 1), access(read_only, 2), optimize("3")))

#else

#define __hint_set_iter_counter__ [[nothrow]]
#define __hint_set_def_key_size__ [[nothrow]]
#define __hint_set_def_iv_size__ [[nothrow]]
#define __hint_prepare_secure_keys__ [[]]
#define __hint_cipher_transformation__ [[]]

#endif

#define __temp_cipher_exec__ template <typename cipher_mode>


enum class e_operation_mode
{
    CBC = 0,
    GCM,
    EAX,
    CFB, 
    OFB,
    CTR
};

enum class e_cfb_algorithm
{
    AES = 0,
    BLOWFISH,
    CAST128,
    CAST256,
    IDEA,
    RC2,
    RC5,
    __COUNT
};

/**
 * Algorithm specific key block size, refers to the key size used by the function.
 */
struct e_key_block_size
{
    static const std::uint16_t AES = CryptoPP::AES::DEFAULT_KEYLENGTH, BLOWFISH = CryptoPP::Blowfish::DEFAULT_KEYLENGTH, TWOFISH = CryptoPP::Twofish::DEFAULT_KEYLENGTH,
                               CAST128 = CryptoPP::CAST128::DEFAULT_KEYLENGTH, CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH, IDEA = CryptoPP::IDEA::DEFAULT_KEYLENGTH,
                               RC2 = CryptoPP::RC2::DEFAULT_KEYLENGTH, RC5 = CryptoPP::RC5::DEFAULT_KEYLENGTH, RC6 = CryptoPP::RC6::DEFAULT_KEYLENGTH,
                               MARS = CryptoPP::MARS::DEFAULT_KEYLENGTH, SERPENT = CryptoPP::Serpent::DEFAULT_KEYLENGTH, GOST = CryptoPP::GOST::DEFAULT_KEYLENGTH,
                               ARIA = CryptoPP::ARIA::BLOCKSIZE, HIGHT = CryptoPP::HIGHT::BLOCKSIZE * 2, LEA = CryptoPP::LEA::DEFAULT_KEYLENGTH, SEED = CryptoPP::SEED::DEFAULT_KEYLENGTH,
                               SPECK128 = CryptoPP::SPECK128::DEFAULT_KEYLENGTH, SIMON128 = CryptoPP::SIMON128::DEFAULT_KEYLENGTH;
};

/**
 * Algorithm specific initialization vector block size reference
 */
struct e_iv_block_size
{
    static const std::uint16_t AES = CryptoPP::AES::BLOCKSIZE, BLOWFISH = CryptoPP::Blowfish::BLOCKSIZE, TWOFISH = CryptoPP::Twofish::BLOCKSIZE, CAST128 = CryptoPP::CAST128::BLOCKSIZE,
                               CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH, IDEA = CryptoPP::IDEA::BLOCKSIZE, RC2 = CryptoPP::RC2::BLOCKSIZE, RC5 = CryptoPP::RC5::BLOCKSIZE,
                               RC6 = CryptoPP::RC6::BLOCKSIZE, MARS = CryptoPP::MARS::BLOCKSIZE, SERPENT = CryptoPP::Serpent::BLOCKSIZE, GOST = CryptoPP::GOST::BLOCKSIZE * 2,
                               ARIA = CryptoPP::ARIA::BLOCKSIZE, HIGHT = CryptoPP::HIGHT::BLOCKSIZE * 2, LEA = CryptoPP::LEA::BLOCKSIZE, SEED = CryptoPP::SEED::BLOCKSIZE,
                               SIMON128 = CryptoPP::SIMON128::BLOCKSIZE, SPECK128 = CryptoPP::SPECK128::BLOCKSIZE;
};

/*                      Type Alias                       *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/**
 * type alias for more readability, camel case makes it look like shit otherwise...
 */
using byte = CryptoPP::byte;
using string_t = std::basic_string<char>;
using string_view_t = std::basic_string_view<char>;
using transformer_filter_t = CryptoPP::StreamTransformationFilter;
using entropy_seed_t = CryptoPP::AutoSeededRandomPool;
using string_sink_t = CryptoPP::StringSink;
using string_source_t = CryptoPP::StringSource;
using hex_encoder_t = CryptoPP::HexEncoder;
using hex_decoder_t = CryptoPP::HexDecoder;
using sha256_hmac_t = CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>;
using sec_byte_block_t = CryptoPP::SecByteBlock;

using cfb_aes_encryption_t = CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption;
using cfb_blowfish_encryption_t = CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption;
using cfb_cast128_encryption_t = CryptoPP::CFB_Mode<CryptoPP::CAST128>::Encryption;
using cfb_cast256_encryption_t = CryptoPP::CFB_Mode<CryptoPP::CAST256>::Encryption;
using cfb_idea_encryption_t = CryptoPP::CFB_Mode<CryptoPP::IDEA>::Encryption;
using cfb_rc2_encryption_t = CryptoPP::CFB_Mode<CryptoPP::RC2>::Encryption;
using cfb_rc5_encryption_t = CryptoPP::CFB_Mode<CryptoPP::RC5>::Encryption;

using cfb_aes_decryption_t = CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption;
using cfb_blowfish_decryption_t = CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption;
using cfb_cast128_decryption_t = CryptoPP::CFB_Mode<CryptoPP::CAST128>::Decryption;
using cfb_cast256_decryption_t = CryptoPP::CFB_Mode<CryptoPP::CAST256>::Decryption;
using cfb_idea_decryption_t = CryptoPP::CFB_Mode<CryptoPP::IDEA>::Decryption;
using cfb_rc2_decryption_t = CryptoPP::CFB_Mode<CryptoPP::RC2>::Decryption;
using cfb_rc5_decryption_t = CryptoPP::CFB_Mode<CryptoPP::RC5>::Decryption;

/*                      Structure                        *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


typedef struct alignas(void *)
{
    string_t error_msg{""};
    bool has_error{false};
} error_frame;

template <typename return_t> struct alignas(void *) op_frame
{
    return_t result{};
    error_frame error{};
};

typedef struct alignas(void *)
{
    sec_byte_block_t key;
    sec_byte_block_t iv;
} secure_byte_pair;

typedef op_frame<string_t> encryption_result;

typedef op_frame<string_t> decryption_result;

typedef struct alignas(void *)
{
    std::uint16_t secure_key{};
    std::uint16_t secure_ivector{};
} mode_of_operation_map;

typedef struct alignas(void *)
{
    std::unordered_map<e_cfb_algorithm, mode_of_operation_map> cfb{};
} operation_mode;


/**
 * CFB Mode of Operation Secure Key/Initialization-Vector block size aggregation.
 */
std::unordered_map<e_cfb_algorithm, mode_of_operation_map> cfb_map_block{
    {e_cfb_algorithm::AES, mode_of_operation_map{.secure_key{e_key_block_size::AES}, .secure_ivector{e_iv_block_size::AES}}},
    {e_cfb_algorithm::BLOWFISH, mode_of_operation_map{.secure_key{e_key_block_size::BLOWFISH}, .secure_ivector{e_iv_block_size::BLOWFISH}}},
    {e_cfb_algorithm::CAST128, mode_of_operation_map{.secure_key{e_key_block_size::CAST128}, .secure_ivector{e_iv_block_size::CAST128}}},
    {e_cfb_algorithm::CAST256, mode_of_operation_map{.secure_key{e_key_block_size::CAST256}, .secure_ivector{e_iv_block_size::CAST256}}},
    {e_cfb_algorithm::IDEA, mode_of_operation_map{.secure_key{e_key_block_size::IDEA}, .secure_ivector{e_iv_block_size::IDEA}}},
    {e_cfb_algorithm::RC2, mode_of_operation_map{.secure_key{e_key_block_size::RC2}, .secure_ivector{e_iv_block_size::RC2}}},
    {e_cfb_algorithm::RC5, mode_of_operation_map{.secure_key{e_key_block_size::RC5}, .secure_ivector{e_iv_block_size::RC5}}},
};

/*                      Class                            *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
class ByteCrypt
{
    std::unique_ptr<string_t> secret_key = std::make_unique<string_t>("");
    std::uint16_t cipher_iteration_count = DEFAULT_CIPHER_ITERATION_COUNTER;
    std::uint16_t default_sec_key_size = DEFAULT_SEC_BLOCK_KEY_SIZE;
    std::uint16_t default_sec_iv_size = DEFAULT_SEC_BLOCK_IV_SIZE;

    operation_mode op_mode{
       .cfb{cfb_map_block}, // CFB mode of operation supported algorithms and key/initialization vector block size
    };

  public:
    inline ByteCrypt() noexcept = default;
    inline ByteCrypt(const ByteCrypt &o_instance) noexcept
    {
        this->__constructor_copy_handler(o_instance);
    };
    inline ByteCrypt &operator=(const ByteCrypt &o_instance) noexcept
    {
        this->__constructor_copy_handler(o_instance);
        return *this;
    };
    inline ByteCrypt(ByteCrypt &&o_instance) noexcept
    {
        this->__constructor_copy_handler(o_instance);
    };
    inline ByteCrypt &operator=(ByteCrypt &&o_instance) noexcept
    {
        this->__constructor_copy_handler(o_instance);
        return *this;
    };
    inline ByteCrypt(const string_view_t initial_secret_key) noexcept
    {
        *this->secret_key = initial_secret_key;
    };
    inline ByteCrypt(const string_view_t &initial_secret_key, const byte key[], const byte iv[], const std::uint16_t key_size, const std::uint16_t iv_size) noexcept
    {
        *this->secret_key = (string_t)initial_secret_key;
    };
    inline const bool operator==(const ByteCrypt &o_instance) const noexcept
    {
        return this->secret_key.get()->compare(o_instance.secret_key.get()->c_str()) == 0;
    };
    inline const bool operator!=(const ByteCrypt &o_instance) const noexcept
    {
        return this->secret_key.get()->compare(o_instance.secret_key.get()->c_str()) != 0;
    };


    __hint_cipher_transformation__ const encryption_result cfb_encrypt(const string_t &buffer, const string_t &secret, const e_cfb_algorithm algorithm = e_cfb_algorithm::AES)
    {
        encryption_result result{.error{.has_error{false}}};
        try
        {
            if (buffer.empty() || secret.empty())
                throw std::runtime_error("Secret of buffer cannot be empty!");
            string_t target, r0;
            entropy_seed_t entropy;
            byte salt[16u];
            entropy.GenerateBlock(salt, sizeof(salt));

            sec_byte_block_t secure_key, initialization_vector;
            this->__prepare_cfb_secure_keys(secret, secure_key, initialization_vector, salt, sizeof(salt), algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("Error during secure key/iv prepare!");
            else if (algorithm == e_cfb_algorithm::AES)
                this->__cfb_execute<cfb_aes_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::BLOWFISH)
                this->__cfb_execute<cfb_blowfish_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::CAST128)
                this->__cfb_execute<cfb_cast128_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::CAST256)
                this->__cfb_execute<cfb_cast256_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::IDEA)
                this->__cfb_execute<cfb_idea_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::RC2)
                this->__cfb_execute<cfb_rc2_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cfb_algorithm::RC5)
                this->__cfb_execute<cfb_rc5_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else
                throw std::invalid_argument("invalid cfb algorithm!");

            const string_t r2(string_t(reinterpret_cast<char *>(salt), sizeof(salt)) + r0);
            string_source_t(r2, true, new hex_encoder_t(new string_sink_t(target)));
            result.result = std::move(target);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    };

    __hint_cipher_transformation__ const decryption_result cfb_decrypt(const string_t &buffer, const string_t &secret, const e_cfb_algorithm algorithm = e_cfb_algorithm::AES)
    {
        decryption_result result{.error{.has_error{false}}};
        try
        {
            byte salt[16];
            string_t rd, r0;
            string_source_t(buffer, true, new hex_decoder_t(new string_sink_t(rd)));
            memcpy(salt, rd.data(), sizeof(salt));
            string_t ciphertext(rd.substr(sizeof(salt)));
            sec_byte_block_t secure_key, initialization_vector;
            this->__prepare_cfb_secure_keys(secret, secure_key, initialization_vector, salt, sizeof(salt), algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("error during key/iv preparation!");

            if (algorithm == e_cfb_algorithm::AES)
                this->__cfb_execute<cfb_aes_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::BLOWFISH)
                this->__cfb_execute<cfb_blowfish_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::CAST128)
                this->__cfb_execute<cfb_cast128_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::CAST256)
                this->__cfb_execute<cfb_cast256_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::IDEA)
                this->__cfb_execute<cfb_idea_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::RC2)
                this->__cfb_execute<cfb_rc2_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cfb_algorithm::RC5)
                this->__cfb_execute<cfb_rc5_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else
                throw std::invalid_argument("invalid cfb algorithm!");

            result.result = std::move(r0);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    };


    /**
     *
     * Set cipher iteration count value.
     * @param std::size_t new number of iterations.
     * @returns void
     *
     */
    __hint_set_iter_counter__ inline void set_cipher_iteration_counter(const std::size_t iterations) noexcept
    {
        if (iterations < 10000000UL)
        {
            this->cipher_iteration_count = iterations;
        }
    };

    /**
     *
     * Set default secure block key size.
     * @param std::uint16_t key size
     * @returns void
     *
     */
    __hint_set_def_key_size__ inline void set_sec_block_key_size(const std::uint16_t key_size) noexcept
    {
        if (key_size >= 8u && key_size <= 256u)
            this->default_sec_key_size = key_size;
    };

    /**
     *
     * Set default secure initialization vector size.
     * @param std::uint16_t initialization vector size
     * @returns void
     *
     */
    __hint_set_def_iv_size__ inline void set_sec_block_iv_size(const std::uint16_t iv_size) noexcept
    {
        if (iv_size >= 8u && iv_size <= 256u)
            this->default_sec_iv_size = iv_size;
    };

    ~ByteCrypt() {};

  private:

    __temp_cipher_exec__ inline void __cfb_execute(sec_byte_block_t &key, sec_byte_block_t &iv, const string_t &source, string_t &output)
    {
        cipher_mode executor;
        executor.SetKeyWithIV(key, key.size(), iv);
        string_source_t(source, true, new transformer_filter_t(executor, new string_sink_t(output)));
    };

    __hint_prepare_secure_keys__ inline void __prepare_cfb_secure_keys(const string_t &cipher, sec_byte_block_t &key, sec_byte_block_t &iv, const byte *salt, const std::size_t salt_size,
                                                                       const e_cfb_algorithm algorithm)
    {
        sha256_hmac_t hmac;
        const std::uint16_t key_size = this->op_mode.cfb.at(algorithm).secure_key;
        const std::uint16_t iv_size = this->op_mode.cfb.at(algorithm).secure_ivector;

        key.CleanNew(key_size);
        iv.CleanNew(iv_size);
        hmac.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
        hmac.DeriveKey(iv, iv.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
    };

    inline void __constructor_copy_handler(const ByteCrypt &o_instance) noexcept
    {
        if (*this != o_instance)
        {
            *this->secret_key = *o_instance.secret_key;
            this->cipher_iteration_count = o_instance.cipher_iteration_count;
            this->default_sec_iv_size = o_instance.default_sec_iv_size;
            this->default_sec_key_size = o_instance.default_sec_key_size;
        }
    };
};
}; // namespace ByteCryptModule
#endif

#endif

#endif

#endif