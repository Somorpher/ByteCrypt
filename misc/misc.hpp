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
#include <crypto++/base64.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/pwdbased.h>
#include <crypto++/rijndael.h>
#include <crypto++/rsa.h>
#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <crypto++/blake2.h>
#include <cryptopp/cryptlib.h>
#include <crypto++/ripemd.h>
#include <cryptopp/pssr.h>
#include <crypto++/tiger.h>
#include <crypto++/twofish.h>
#include <crypto++/whrlpool.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__

/**
 * Utility within namespace to avoid namespace pollution.
 */
namespace ByteCryptModule
{

/**
 * defining some top level macros, these are compiler optimization attributes, some of them are very strict with
 * argument ordering for example access attribute might be affected if function signature changes but not
 * the macro definition as well. Defining these macros here makes the code more readable also, but they
 * only work with g++ or clang compilers.
 */

/*                      Attribution                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)


#define __hint_hash__ __attribute__((stack_protect, zero_call_used_regs("used"), warn_unused_result, access(read_only, 1), optimize(3)))
#define __hint_base64_encode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_base64_decode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_hex_encode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_hex_decode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_generate_random_bytes__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), optimize("3")))

#else

#define __hint_hash__ [[nodiscard]]
#define __hint_base64_encode__ [[nodiscard]]
#define __hint_base64_decode__ [[nodiscard]]
#define __hint_hex_encode__ [[nodiscard]]
#define __hint_hex_decode__ [[nodiscard]]
#define __hint_generate_random_bytes__ [[warn_unused_result]]

#endif

#define __temp_byte_crypt__ template <typename std::size_t key_size_t = e_key_block_size::AES, typename std::size_t iv_size_t = e_iv_block_size::AES>
#define __temp_cipher_exec__ template <typename cipher_mode>

enum class e_hash_algo_option
{
    SHA1 = 0,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    MD5,
    RIPEMD160,
    WHIRLPOOL,
    BLAKE2,
    TIGER,
};

/*                      Type Alias                       *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/**
 * type alias for more readability, camel case makes it look like shit otherwise...
 */
using byte = CryptoPP::byte;
using string_t = std::basic_string<char>;
using string_view_t = std::basic_string_view<char>;
using cbc_cipher_t = CryptoPP::Rijndael;
using entropy_seed_t = CryptoPP::AutoSeededRandomPool;
using string_sink_t = CryptoPP::StringSink;
using string_source_t = CryptoPP::StringSource;
using hex_encoder_t = CryptoPP::HexEncoder;
using hex_decoder_t = CryptoPP::HexDecoder;
using base64_encoder_t = CryptoPP::Base64Encoder;
using base64_decoder_t = CryptoPP::Base64Decoder;
using sha1_t = CryptoPP::SHA1;
using sha224_t = CryptoPP::SHA224;
using sha256_t = CryptoPP::SHA256;
using sha384_t = CryptoPP::SHA384;
using sha512_t = CryptoPP::SHA512;
using md5_t = CryptoPP::Weak1::MD5;
using ripemd160_t = CryptoPP::RIPEMD160;
using whirlpool_t = CryptoPP::Whirlpool;
using blake2_t = CryptoPP::BLAKE2b;
using tiger_t = CryptoPP::Tiger;
using hash_transformer_t = CryptoPP::HashTransformation;
using hash_filter_t = CryptoPP::HashFilter;
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


/*                      Class                            *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
class ByteCrypt
{
    std::unique_ptr<string_t> secret_key = std::make_unique<string_t>("");
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

    /**
     * Hash buffer with specified algorithm and return digest.
     * @param string_view_t buffer to hash
     * @param e_hash_algo_option hash algorithm
     * @returns op_frame<string_t> structure containing error and result.
     */
    __hint_hash__ const op_frame<string_t> hash(const string_view_t buffer, const e_hash_algo_option sha = e_hash_algo_option::SHA256) const
    {
        op_frame<string_t> return_block{.result{}, .error{.error_msg{}, .has_error{false}}};
        std::unique_ptr<hash_transformer_t> algo;
        try
        {
            switch ((std::uint16_t)sha)
            {
            case (std::uint16_t)e_hash_algo_option::SHA1:
                algo = std::make_unique<sha1_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::SHA224:
                algo = std::make_unique<sha224_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::SHA256:
                algo = std::make_unique<sha256_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::SHA384:
                algo = std::make_unique<sha384_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::SHA512:
                algo = std::make_unique<sha512_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::BLAKE2:
                algo = std::make_unique<blake2_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::MD5:
                algo = std::make_unique<md5_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::RIPEMD160:
                algo = std::make_unique<ripemd160_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::TIGER:
                algo = std::make_unique<tiger_t>();
                break;
            case (std::uint16_t)e_hash_algo_option::WHIRLPOOL:
                algo = std::make_unique<whirlpool_t>();
                break;
            }
            string_source_t(buffer.data(), true, new hash_filter_t(*algo, new hex_encoder_t(new string_sink_t(return_block.result))));
        }
        catch (const std::exception &e)
        {
            return_block.error.has_error = true;
            return_block.error.error_msg = e.what();
        }
        return return_block;
    };

    /**
     *
     * Generate Random Bytes using secure system entropy generator with 16 bytes output block size.
     * @returns op_frame<string_t> the random generated string block frame
     *
     */
    __hint_generate_random_bytes__ const op_frame<string_t> generate_random_bytes(void)
    {
        op_frame<string_t> random_block{.result{}, .error{.error_msg{}, .has_error{false}}};
        try
        {
            entropy_seed_t entropy;
            byte random_bytes[16];
            entropy.GenerateBlock(random_bytes, sizeof(random_bytes));
            string_source_t(random_bytes, sizeof(random_bytes), true, new hex_encoder_t(new string_sink_t(random_block.result)));
        }
        catch (const std::exception &e)
        {
            random_block.error.has_error = true;
            random_block.error.error_msg = e.what();
            random_block.result.clear();
        }
        return random_block;
    };

    
    /**
     *
     * Shift block to right by "shift_pos" positions, "shift_pos", shift_pos does not usually exceed values such
     * as(100-200).
     * @param string_view_t& block to shift
     * @param int the number of positions to r-move
     * @returns string_t the right shifted block
     *
     */
    const string_t block_rshift(const string_view_t block, const std::uint16_t shift_pos = 3)
    {
        if (block.empty())
            return "";
        string_t local_bytes;
        local_bytes.reserve(block.length());
        for (const char index_byte : block)
            local_bytes += static_cast<char>((static_cast<int>(index_byte) + (shift_pos % 256)) % 256);
        return local_bytes;
    }

    /**
     *
     * Shift block to left by "shift_pos" positions, "shift_pos", shift_pos does not usually exceed values such
     * as(100-200).
     * @param string_view_t& block to shift
     * @param int the number of positions to l-move
     * @returns string_t the left shifted block
     *
     */
    const string_t block_lshift(const string_view_t block, const std::uint16_t shift_pos = 3)
    {
        if (block.empty())
            return "";
        string_t local_bytes;
        local_bytes.reserve(block.length());
        for (const char index_byte : block)
            local_bytes += static_cast<char>((static_cast<int>(index_byte) - (shift_pos % 256) + 256) % 256);
        return local_bytes;
    };

    /**
     * base64 encoding of plain_text buffer
     * @param string_view_t& data to encode using base64 encoding
     * @returns string_t encoded data
     */
    __hint_base64_encode__ inline const string_t base64_encode(const string_view_t &plain_text)
    {
        string_t b64_encoded;
        string_source_t(plain_text.data(), true, new base64_encoder_t(new string_sink_t(b64_encoded)));
        return b64_encoded;
    };

    /**
     * decode encoded_cipher using base64.
     * @param string_view_t& encoded cipher to decode
     * @returns string_t base64 decoded data
     */
    __hint_base64_decode__ inline const string_t base64_decode(const string_view_t &encoded_cipher)
    {
        string_t b64_decoded;
        string_source_t(encoded_cipher.data(), true, new base64_decoder_t(new string_sink_t(b64_decoded)));
        return b64_decoded;
    };

    /**
     * encode plain_text with hex
     * @param string_view_t& data to encode
     * @returns string_t hex encoded data
     */
    __hint_hex_encode__ inline const string_t hex_encode(const string_view_t &plain_text)
    {
        std::ostringstream parser;
        for (const unsigned char _byte : plain_text)
            parser << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_byte);
        return parser.str();
    };

    /**
     * decode hex_encoded data
     * @param string_view_t& hex encoded data
     * @returns string_t hex decoded data
     */
    __hint_hex_decode__ inline const string_t hex_decode(const string_view_t &hex_encoded)
    {
        if (hex_encoded.length() % 2 != 0 || hex_encoded.length() >= UINT64_MAX) [[unlikely]]
        {
            return "";
        }
        string_t hex_decoded;
        hex_decoded.reserve(hex_encoded.length() / 2);
        for (std::size_t _i{0}; _i < hex_encoded.length(); _i += 2)
            hex_decoded.push_back(static_cast<char>(std::stoi(string_t(hex_encoded.substr(_i, 2)), nullptr, 16)));

        return hex_decoded;
    };

    ~ByteCrypt() {};

  private:
    inline void __constructor_copy_handler(const ByteCrypt &o_instance) noexcept
    {
        if (*this != o_instance)
        {
            *this->secret_key = *o_instance.secret_key;
        }
    };
};
}; // namespace ByteCryptModule
#endif

#endif

#endif

#endif