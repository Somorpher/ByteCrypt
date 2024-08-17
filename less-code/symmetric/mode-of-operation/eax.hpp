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
#include <crypto++/eax.h>
#include <crypto++/filters.h>
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
#include <crypto++/ripemd.h>
#include <crypto++/secblock.h>
#include <crypto++/seed.h>
#include <crypto++/serpent.h>
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

/**
 * defining some top level macros, these are compiler optimization attributes, some of them are very strict with
 * argument ordering for example access attribute might be affected if function signature changes but not
 * the macro definition as well. Defining these macros here makes the code more readable also, but they
 * only work with g++ or clang compilers.
 */

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


enum class e_eax_algorithm
{
    AES = 0,
    BLOWFISH,
    CAST128,
    CAST256,
    IDEA,
    RC5,
    RC6,
    MARS,
    SERPENT,
    GOST,
    LEA,
    SPECK128,
    SEED,
    SIMON128,
    HIGHT,
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
using auth_decryption_filter_t = CryptoPP::AuthenticatedDecryptionFilter;
using auth_encryption_filter_t = CryptoPP::AuthenticatedEncryptionFilter;

using eax_aes_encryption_t = CryptoPP::EAX<CryptoPP::AES>::Encryption;
using eax_blowfish_encryption_t = CryptoPP::EAX<CryptoPP::Blowfish>::Encryption;
using eax_serpent_encryption_t = CryptoPP::EAX<CryptoPP::Serpent>::Encryption;
using eax_cast128_encryption_t = CryptoPP::EAX<CryptoPP::CAST128>::Encryption;
using eax_cast256_encryption_t = CryptoPP::EAX<CryptoPP::CAST256>::Encryption;
using eax_idea_encryption_t = CryptoPP::EAX<CryptoPP::IDEA>::Encryption;
using eax_rc5_encryption_t = CryptoPP::EAX<CryptoPP::RC5>::Encryption;
using eax_rc6_encryption_t = CryptoPP::EAX<CryptoPP::RC6>::Encryption;
using eax_gost_encryption_t = CryptoPP::EAX<CryptoPP::GOST>::Encryption;
using eax_mars_encryption_t = CryptoPP::EAX<CryptoPP::MARS>::Encryption;
using eax_seed_encryption_t = CryptoPP::EAX<CryptoPP::SEED>::Encryption;
using eax_speck128_encryption_t = CryptoPP::EAX<CryptoPP::SPECK128>::Encryption;
using eax_lea_encryption_t = CryptoPP::EAX<CryptoPP::LEA>::Encryption;
using eax_simon128_encryption_t = CryptoPP::EAX<CryptoPP::SIMON128>::Encryption;
using eax_hight_encryption_t = CryptoPP::EAX<CryptoPP::HIGHT>::Encryption;

using eax_aes_decryption_t = CryptoPP::EAX<CryptoPP::AES>::Decryption;
using eax_blowfish_decryption_t = CryptoPP::EAX<CryptoPP::Blowfish>::Decryption;
using eax_serpent_decryption_t = CryptoPP::EAX<CryptoPP::Serpent>::Decryption;
using eax_cast128_decryption_t = CryptoPP::EAX<CryptoPP::CAST128>::Decryption;
using eax_cast256_decryption_t = CryptoPP::EAX<CryptoPP::CAST256>::Decryption;
using eax_idea_decryption_t = CryptoPP::EAX<CryptoPP::IDEA>::Decryption;
using eax_rc5_decryption_t = CryptoPP::EAX<CryptoPP::RC5>::Decryption;
using eax_rc6_decryption_t = CryptoPP::EAX<CryptoPP::RC6>::Decryption;
using eax_gost_decryption_t = CryptoPP::EAX<CryptoPP::GOST>::Decryption;
using eax_mars_decryption_t = CryptoPP::EAX<CryptoPP::MARS>::Decryption;
using eax_seed_decryption_t = CryptoPP::EAX<CryptoPP::SEED>::Decryption;
using eax_speck128_decryption_t = CryptoPP::EAX<CryptoPP::SPECK128>::Decryption;
using eax_lea_decryption_t = CryptoPP::EAX<CryptoPP::LEA>::Decryption;
using eax_simon128_decryption_t = CryptoPP::EAX<CryptoPP::SIMON128>::Decryption;
using eax_hight_decryption_t = CryptoPP::EAX<CryptoPP::HIGHT>::Decryption;

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
    std::unordered_map<e_eax_algorithm, mode_of_operation_map> eax{};
} operation_mode;

/**
 * EAX Mode of Operation Secure Key/Initialization-Vector block size aggregation.
 */
std::unordered_map<e_eax_algorithm, mode_of_operation_map> eax_map_block{
    {e_eax_algorithm::AES, mode_of_operation_map{.secure_key{e_key_block_size::AES}, .secure_ivector{e_iv_block_size::AES}}},
    {e_eax_algorithm::BLOWFISH, mode_of_operation_map{.secure_key{e_key_block_size::BLOWFISH}, .secure_ivector{e_iv_block_size::BLOWFISH}}},
    {e_eax_algorithm::CAST128, mode_of_operation_map{.secure_key{e_key_block_size::CAST128}, .secure_ivector{e_iv_block_size::CAST128}}},
    {e_eax_algorithm::CAST256, mode_of_operation_map{.secure_key{e_key_block_size::CAST256}, .secure_ivector{e_iv_block_size::CAST256}}},
    {e_eax_algorithm::GOST, mode_of_operation_map{.secure_key{e_key_block_size::GOST}, .secure_ivector{e_iv_block_size::GOST}}},
    {e_eax_algorithm::HIGHT, mode_of_operation_map{.secure_key{e_key_block_size::HIGHT}, .secure_ivector{e_iv_block_size::HIGHT}}},
    {e_eax_algorithm::IDEA, mode_of_operation_map{.secure_key{e_key_block_size::IDEA}, .secure_ivector{e_iv_block_size::IDEA}}},
    {e_eax_algorithm::LEA, mode_of_operation_map{.secure_key{e_key_block_size::LEA}, .secure_ivector{e_iv_block_size::LEA}}},
    {e_eax_algorithm::MARS, mode_of_operation_map{.secure_key{e_key_block_size::MARS}, .secure_ivector{e_iv_block_size::MARS}}},
    {e_eax_algorithm::RC5, mode_of_operation_map{.secure_key{e_key_block_size::RC5}, .secure_ivector{e_iv_block_size::RC5}}},
    {e_eax_algorithm::RC6, mode_of_operation_map{.secure_key{e_key_block_size::RC6}, .secure_ivector{e_iv_block_size::RC6}}},
    {e_eax_algorithm::SEED, mode_of_operation_map{.secure_key{e_key_block_size::SEED}, .secure_ivector{e_iv_block_size::SEED}}},
    {e_eax_algorithm::SERPENT, mode_of_operation_map{.secure_key{e_key_block_size::SERPENT}, .secure_ivector{e_iv_block_size::SERPENT}}},
    {e_eax_algorithm::SIMON128, mode_of_operation_map{.secure_key{e_key_block_size::SIMON128}, .secure_ivector{e_iv_block_size::SIMON128}}},
    {e_eax_algorithm::SPECK128, mode_of_operation_map{.secure_key{e_key_block_size::SPECK128}, .secure_ivector{e_iv_block_size::SPECK128}}},
};

/*                      Class                            *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
class ByteCrypt
{
    std::unique_ptr<string_t> secret_key = std::make_unique<string_t>("");
    std::uint16_t cipher_iteration_count = DEFAULT_CIPHER_ITERATION_COUNTER;
    std::uint16_t default_sec_key_size = DEFAULT_SEC_BLOCK_KEY_SIZE;
    std::uint16_t default_sec_iv_size = DEFAULT_SEC_BLOCK_IV_SIZE;

    static constexpr std::array<std::uint16_t, 5> rsa_key_size_options{512u, 1024u, 2048u, 3072u, 4096u};
    operation_mode op_mode{
        .eax{eax_map_block}, // EAX mode of operation supported algorithms and key/initialization vector block size
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

    __hint_cipher_transformation__ const encryption_result eax_encrypt(const string_t &plaintext_cipher, const string_t &secret, const e_eax_algorithm algorithm = e_eax_algorithm::AES)
    {
        encryption_result result{.error{.has_error{false}}};
        try
        {
            string_t encrypted_block, encoded_block;
            sec_byte_block_t secure_key, initialization_vector;
            this->__prepare_eax_secure_keys(secret, secure_key, initialization_vector, algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("error during key/iv preparation!");
            if (algorithm == e_eax_algorithm::AES)
                this->__eax_execute<eax_aes_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::BLOWFISH)
                this->__eax_execute<eax_blowfish_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::CAST128)
                this->__eax_execute<eax_cast128_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::CAST256)
                this->__eax_execute<eax_cast256_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::GOST)
                this->__eax_execute<eax_gost_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::HIGHT)
                this->__eax_execute<eax_hight_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::IDEA)
                this->__eax_execute<eax_idea_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::LEA)
                this->__eax_execute<eax_lea_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::MARS)
                this->__eax_execute<eax_mars_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::RC5)
                this->__eax_execute<eax_rc5_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::RC6)
                this->__eax_execute<eax_rc6_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::SEED)
                this->__eax_execute<eax_seed_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::SERPENT)
                this->__eax_execute<eax_serpent_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::SIMON128)
                this->__eax_execute<eax_simon128_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_eax_algorithm::SPECK128)
                this->__eax_execute<eax_speck128_encryption_t>(secure_key, initialization_vector, plaintext_cipher, encrypted_block, encoded_block);
            else
                throw std::invalid_argument("invalid eax algorithm.");

            result.result = std::move(encoded_block);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    }

    __hint_cipher_transformation__ const decryption_result eax_decrypt(const string_t &encrypted_cipher, const string_t &secret, const e_eax_algorithm algorithm = e_eax_algorithm::AES)
    {
        decryption_result result{.error{.has_error{false}}};
        try
        {
            const std::uint16_t iv_block_size(this->op_mode.eax.at(algorithm).secure_ivector);
            string_t decrypted_block, decoded_block;
            string_source_t(encrypted_cipher, true, new hex_decoder_t(new string_sink_t(decoded_block)));
            sec_byte_block_t secure_key, initialization_vector;
            initialization_vector = sec_byte_block_t((const byte *)decoded_block.data(), e_iv_block_size::AES);
            this->__prepare_eax_secure_keys(secret, secure_key, initialization_vector, algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("error during key/iv preparation!");
            if (algorithm == e_eax_algorithm::AES)
                this->__eax_reverse_execution<eax_aes_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::BLOWFISH)
                this->__eax_reverse_execution<eax_blowfish_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::CAST128)
                this->__eax_reverse_execution<eax_cast128_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::CAST256)
                this->__eax_reverse_execution<eax_cast256_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::GOST)
                this->__eax_reverse_execution<eax_gost_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::HIGHT)
                this->__eax_reverse_execution<eax_hight_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::IDEA)
                this->__eax_reverse_execution<eax_idea_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::LEA)
                this->__eax_reverse_execution<eax_lea_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::MARS)
                this->__eax_reverse_execution<eax_mars_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::RC5)
                this->__eax_reverse_execution<eax_rc5_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::RC6)
                this->__eax_reverse_execution<eax_rc6_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::SEED)
                this->__eax_reverse_execution<eax_seed_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::SERPENT)
                this->__eax_reverse_execution<eax_serpent_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::SIMON128)
                this->__eax_reverse_execution<eax_simon128_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_eax_algorithm::SPECK128)
                this->__eax_reverse_execution<eax_speck128_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else
                throw std::invalid_argument("invalid eax algorithm provided!");
            result.result = std::move(decrypted_block);
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
    
    __temp_cipher_exec__ inline void __eax_execute(sec_byte_block_t &key, sec_byte_block_t &iv, const string_t &plaintext_cipher, string_t &encrypted_block, string_t &encoded_block)
    {
        cipher_mode encryption;
        encryption.SetKeyWithIV(key, key.size(), iv, iv.size());
        string_source_t(plaintext_cipher, true, new auth_encryption_filter_t(encryption, new string_sink_t(encrypted_block)));
        encrypted_block = string_t((const char *)iv.data(), iv.size()) + encrypted_block;
        string_source_t(encrypted_block, true, new hex_encoder_t(new string_sink_t(encoded_block)));
    };

    __temp_cipher_exec__ inline void __eax_reverse_execution(sec_byte_block_t &key, sec_byte_block_t &iv, const std::uint16_t iv_block_size, const string_t &decoded_block,
                                                             string_t &decrypted_block)
    {
        iv = sec_byte_block_t((const byte *)decoded_block.data(), iv_block_size);
        string_t ciphertext = decoded_block.substr(iv_block_size);
        cipher_mode decryption;
        decryption.SetKeyWithIV(key, key.size(), iv, iv.size());
        string_source_t(ciphertext, true, new auth_decryption_filter_t(decryption, new string_sink_t(decrypted_block)));
    };

    __hint_prepare_secure_keys__ inline void __prepare_eax_secure_keys(const string_t &secret, sec_byte_block_t &key, sec_byte_block_t &iv, const e_eax_algorithm algorithm)
    {
        CryptoPP::SHA256 hash;
        key.resize(this->op_mode.eax.at(algorithm).secure_key);
        hash.CalculateDigest(key, (const byte *)secret.data(), secret.size());
        iv.resize(this->op_mode.eax.at(algorithm).secure_ivector);
        entropy_seed_t e_gen;
        e_gen.GenerateBlock(iv, iv.size());
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
