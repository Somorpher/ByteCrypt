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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

#define RSA_PUBLIC_KEY_HEADER "-----BEGIN PUBLIC KEY-----\n"
#define RSA_PRIVATE_KEY_HEADER "-----BEGIN RSA PRIVATE KEY-----\n"
#define RSA_PUBLIC_KEY_FOOTER "-----END PUBLIC KEY-----\n"
#define RSA_PRIVATE_KEY_FOOTER "-----END RSA PRIVATE KEY-----\n"
#define RSA_ENCRYPTED_PRIVATE_KEY_HEADER "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
#define RSA_ENCRYPTED_PRIVATE_KEY_FOOTER "-----END ENCRYPTED PRIVATE KEY-----\n"


/**
 * defining some top level macros, these are compiler optimization attributes, some of them are very strict with
 * argument ordering for example access attribute might be affected if function signature changes but not
 * the macro definition as well. Defining these macros here makes the code more readable also, but they
 * only work with g++ or clang compilers.
 */

/*                      Attribution                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)

#define __hint_load_rsa_key__ __attribute__((warn_unused_result, cold, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_generate_rsa_key_der_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_generate_rsa_key_pem_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_sign_message__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_verify_signature__                                                                                                                                                            \
    __attribute__((warn_unused_result, access(read_only, 1), access(read_only, 2), access(read_only, 3), stack_protect, zero_call_used_regs("used"), optimize("3")))
#define __hint_save_rsa_key__ __attribute__((stack_protect, zero_call_used_regs("used"), tainted_args, access(read_only, 1), access(read_only, 2), optimize("3")))
#define __hint_rsa_key_pair_verify__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_rsa_key_pem_set_header__ __attribute__((nothrow, always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_rsa_key_pem_set_footer__ __attribute__((always_inline, nothrow, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_is_rsa_key_size_valid__ __attribute__((nothrow, warn_unused_result, always_inline, const, no_stack_protector, access(read_only, 1), optimize("1")))
#define __hint_is_rsa_key_pem__ __attribute__((warn_unused_result, nothrow, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("1")))
#define __hint_is_rsa_encrypted_key__ __attribute__((nothrow, warn_unused_result, const, always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("0")))
#define __hint_rsa_key_meta_wipe__ __attribute__((const, zero_call_used_regs("used"), warn_unused_result, access(read_only, 1), optimize("2")))
#define __hint_store_secret__ __attribute__((cold, stack_protect, optimize("3"), zero_call_used_regs("used"), access(read_only, 1)))
#define __hint_load_secret_from_file__ __attribute__((cold, warn_unused_result, stack_protect, optimize("3"), zero_call_used_regs("used"), access(read_only, 1)))

#else
#define __hint_load_rsa_key__ [[nodiscard]]
#define __hint_generate_rsa_key_der_pair__ [[nodiscard]]
#define __hint_generate_rsa_key_der_pair__ [[nodiscard]]
#define __hint_sign_message__ [[nodiscard]]
#define __hint_verify_signature__ [[nodiscard]]
#define __hint_save_rsa_key__ [[nodiscard]]
#define __hint_rsa_key_pair_verify__ [[nodiscard]]
#define __hint_rsa_key_pem_set_header__ [[nothrow]]
#define __hint_rsa_key_pem_set_footer__ [[nothrow]]
#define __hint_is_rsa_key_size_valid__ [[nothrow, nodiscard]]
#define __hint_is_rsa_key_pem__ [[nothrow, nodiscard]]
#define __hint_is_rsa_encrypted_key__ [[nothrow, nodiscard]]
#define __hint_rsa_key_meta_wipe__ [[nodiscard]]
#define __hint_store_secret__ [[nodiscard]]
#define __hint_load_secret_from_file__ [[nodiscard]]

#endif

#define __temp_byte_crypt__ template <typename std::size_t key_size_t = e_key_block_size::AES, typename std::size_t iv_size_t = e_iv_block_size::AES>
#define __temp_cipher_exec__ template <typename cipher_mode>

enum class e_rsa_key_pem_version
{
    PUBLIC = 0,
    PRIVATE
};

enum class e_operation_mode
{
    CBC = 0,
    GCM,
    EAX,
    CFB, 
    OFB,
    CTR
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
using transformer_filter_t = CryptoPP::StreamTransformationFilter;
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
using rsa_signature_t = CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer;
using rsa_signature_filter_t = CryptoPP::SignerFilter;
using rsa_signature_verify_t = CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier;
using crypto_exception_t = CryptoPP::Exception;
using sec_byte_block_t = CryptoPP::SecByteBlock;

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

/*                      Class                            *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
class ByteCrypt
{
    std::unique_ptr<string_t> secret_key = std::make_unique<string_t>("");

    static constexpr std::array<std::uint16_t, 5> rsa_key_size_options{512u, 1024u, 2048u, 3072u, 4096u};

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
     * generate a pair of DER RSA keys with rsa_key_size size, size defaults to 2048 bits.
     * @param std::uint16_t rsa key size
     * @returns op_frame<rsa_key_pair_struct> structure with public and private key association, and error info if any!
     */
    __hint_generate_rsa_key_der_pair__ const op_frame<rsa_key_pair_struct> generate_rsa_key_der_pair(const std::uint16_t rsa_key_size = 2048U)
    {
        op_frame<rsa_key_pair_struct> return_block{.result{.public_key{std::nullopt}, .private_key{std::nullopt}, .state{false}}, .error{.error_msg{""}, .has_error{false}}};

        std::function<void(const string_view_t &msg)> reset_block_state([&return_block](const string_view_t &msg) -> void {
            return_block.error.has_error = true;
            return_block.error.error_msg = msg.data();
            return_block.result.state = false;
            if (!return_block.result.private_key->empty())
                return_block.result.private_key->clear();
            if (!return_block.result.public_key->empty())
                return_block.result.public_key->clear();
        });
        if (!this->__is_rsa_key_size_valid(rsa_key_size)) [[unlikely]]
            return return_block;

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

            if (!private_key_result_encoded.empty()) [[likely]]
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
                    throw;
                }
            }
            if (!private_key_result_encoded.empty() && !public_key_result_encoded.empty()) [[likely]]
            {
                return_block.result.private_key = std::move(private_key_result_encoded);
                return_block.result.public_key = std::move(public_key_result_encoded);
                if (this->__rsa_key_pair_verify(return_block.result)) [[likely]]
                {
                    return_block.result.state = true;
                    return_block.error.has_error = false;
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception: " << e.what() << "\n";
            reset_block_state(e.what());
        }
        return return_block;
    };

    /**
     * generate a pair of RSA PEM key pair with rsa_key_size size.
     * @param std::uint16_t rsa key size
     * @returns op_frame<rsa_key_pair_struct> structure with the rsa generated PEM keys.
     */
    __hint_generate_rsa_key_pem_pair__ const op_frame<rsa_key_pair_struct> generate_rsa_key_pem_pair(const std::uint16_t rsa_key_size = 2048U)
    {
        op_frame<rsa_key_pair_struct> rsa_keys = this->generate_rsa_key_der_pair(rsa_key_size);
        if (!this->__is_rsa_key_size_valid(rsa_key_size)) [[unlikely]]
            return rsa_keys;
        try
        {
            string_t private_decoded, public_decoded;
            this->__rsa_key_pem_set_header(private_decoded, false);
            this->__rsa_key_pem_set_header(public_decoded, true);
            private_decoded += rsa_keys.result.private_key.value_or("");
            public_decoded += rsa_keys.result.public_key.value_or("");
            this->__rsa_key_pem_set_footer(private_decoded, false);
            this->__rsa_key_pem_set_footer(public_decoded, true);
            if (private_decoded.empty() || public_decoded.empty()) [[unlikely]]
                throw std::runtime_error("decoded private/public pem key error!");
            rsa_keys.result.private_key = std::move(private_decoded);
            rsa_keys.result.public_key = std::move(public_decoded);
        }
        catch (const std::exception &e)
        {
            rsa_keys.error.has_error = true;
            rsa_keys.error.error_msg = e.what();
            rsa_keys.result.state = false;
            if (rsa_keys.result.private_key.has_value())
                rsa_keys.result.private_key->clear();
            if (rsa_keys.result.public_key.has_value())
                rsa_keys.result.public_key->clear();
        }
        return rsa_keys;
    };

    /**
     * sign message with rsa_key private key, function generates signature and returns it.
     * @param string_view_t message to sign
     * @param string_t& rsa private key for signature generation
     * @returns op_frame<string_t> frame block containing signature as result and error(if any) as state meta-information
     */
    __hint_sign_message__ const op_frame<string_t> sign_message(const string_view_t message, const string_t &rsa_key)
    {
        op_frame<string_t> return_block{.result{}, .error{.error_msg{}, .has_error{true}}};
        if (!this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PRIVATE)) [[unlikely]]
        {
            return_block.error.error_msg = "rsa key size is invalid!";
            return return_block;
        }
        else if (message.empty() || message.length() >= UINT32_MAX) [[unlikely]]
        {
            return_block.error.error_msg = "message too long, cannot be > 4294967295U!";
            return return_block;
        }
        string_t clean_key(this->__rsa_key_meta_wipe(const_cast<string_t &&>(rsa_key)));
        try
        {
            if (clean_key.empty()) [[unlikely]]
            {
                return_block.error.error_msg = "cannot remove rsa key header/footer!\n";
                return return_block;
            }

            string_t private_key_decoded, signature;
            string_source_t(clean_key, true, new base64_decoder_t(new string_sink_t(private_key_decoded)));
            rsa_private_key_t private_key;
            string_source_t private_key_source(private_key_decoded, true);
            private_key.BERDecode(private_key_source);
            rsa_signature_t signer(private_key);
            entropy_seed_t entropy;
            string_source_t(message.data(), true, new rsa_signature_filter_t(entropy, signer, new string_sink_t(signature)));
            string_t encoded_signature;
            string_source_t(signature, true, new base64_encoder_t(new string_sink_t(encoded_signature)));
            return_block.result = encoded_signature;
            return_block.error.has_error = false;
        }
        catch (const std::exception &e)
        {
            return_block.error.error_msg = e.what();
            return_block.error.has_error = true;
            if (return_block.result.empty() == false)
                return_block.result.clear();
        }
        return return_block;
    };

    /**
     * verify message rsa private key signature with signature_str signature, and rsa_key public key
     * @param string_view_t& message to verify signature from
     * @param string_view_t& signature to use
     * @param string_t& RSA public key
     * @returns bool true if verification succeded
     */
    __hint_verify_signature__ const bool verify_signature(const string_view_t &message, const string_view_t &signature_str, const string_t &rsa_key)
    {
        bool verification_result;
        if (!this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PUBLIC)) [[unlikely]]
            return false;
        try
        {
            string_t public_key_decoded;
            string_t pure_key(this->__rsa_key_meta_wipe(const_cast<string_t &&>(rsa_key)));
            string_source_t(pure_key, true, new base64_decoder_t(new string_sink_t(public_key_decoded)));
            rsa_public_key_t public_key;
            string_source_t public_key_source(public_key_decoded, true);
            public_key.BERDecode(public_key_source);
            string_t signature_decoded;
            string_source_t(signature_str.data(), true, new base64_decoder_t(new string_sink_t(signature_decoded)));
            rsa_signature_verify_t verifier(public_key);
            verification_result = verifier.VerifyMessage((const byte *)message.data(), message.length(), (const byte *)signature_decoded.data(), signature_decoded.size());
        }
        catch (const std::exception &e)
        {
            verification_result = false;
        }
        return verification_result;
    };

    /**
     * save rsa_key into path(file name).
     * @param string_t& path to key
     * @param string_view_t& rsa key(public/private)
     * @returns op_frame<bool> true if key saved
     */
    __hint_save_rsa_key__ const op_frame<bool> save_rsa_key(const string_view_t &path, const string_t &rsa_key)
    {
        op_frame<bool> return_block{.result{false}, .error{.error_msg{}, .has_error{true}}};
        try
        {
            if (path.empty()) [[unlikely]]
                throw std::invalid_argument("path to store rsa key not invalid!");
            if (rsa_key.empty()) [[unlikely]]
                throw std::invalid_argument("rsa key value invalid!");

            std::ofstream file_handler(path.data(), std::ios::binary | std::ios::out);
            if (!file_handler.is_open()) [[unlikely]]
                throw std::ofstream::failure::runtime_error("file stream for writing rsa key not open!");
            file_handler << rsa_key;
            file_handler.close();
            return_block.error.has_error = false;
            return_block.result = true;
        }
        catch (const std::exception &e)
        {
            return_block.error.has_error = true;
            return_block.error.error_msg = e.what();
        }
        return return_block;
    };

    /**
     * load rsa key from file_name.
     * @param string_view_t& address of file where key stored.
     * @returns rsa_key_block_load structure containing loaded rsa key
     */
    __hint_load_rsa_key__ const rsa_key_block_load load_rsa_key(const string_view_t &file_name)
    {
        rsa_key_block_load rsa_loader;
        try
        {
            if (file_name.empty()) [[unlikely]]
                throw std::invalid_argument("path to read rsa key not invalid!");

            std::ifstream file_handler(file_name.data(), std::ios::binary | std::ios::in);
            if (!file_handler.is_open()) [[unlikely]]
                throw std::ifstream::failure::runtime_error("file stream for reading rsa key not open!");

            string_t read_key;
            rsa_loader.key.clear();
            do
                rsa_loader.key += read_key += "\n";
            while (std::getline(file_handler, read_key));
            file_handler.close();
            if (!rsa_loader.key.empty()) [[likely]]
                rsa_loader.status = true;
        }
        catch (const std::exception &e)
        {
            rsa_loader.error = e.what();
            rsa_loader.status = false;
            if (!rsa_loader.key.empty())
                rsa_loader.key.clear();
        }
        return rsa_loader;
    };

    /**
     *
     * Store secret(K) within secret_path, if flag "hide" is true, this will preceed the destination file
     * with a "." so it hides it(kind of), default is false.
     * @param string_view_t& secret to store
     * @param string_view_t& path to store
     * @param bool if true it will hide the secret file name
     * @returns op_frame<bool> result secret store
     */
    __hint_store_secret__ op_frame<bool> store_secret(const string_view_t &secret, const string_view_t &secret_path, const bool hide = false) noexcept
    {
        op_frame<bool> return_block{.result{false}, .error{.error_msg{}, .has_error{true}}};
        if (secret.empty() || secret_path.empty())
        {
            return_block.error.error_msg = "empty secret or secret path!";
            return return_block;
        }
        string_t secret_path2;
        try
        {
            if (hide)
            {
                string_t last_path_segment(secret_path.data());
                if (secret_path.find(PATH_SEPARATOR) != string_t::npos)
                {
                    last_path_segment = secret_path.substr(secret_path.find(PATH_SEPARATOR) + 1);
                }
                if (last_path_segment.find(".") != 0)
                {
                    last_path_segment = "." + last_path_segment;
                }
                secret_path2 = std::move(last_path_segment);
            }
            std::ofstream file_descriptor(secret_path2.data(), std::ios::binary);
            if (!file_descriptor.is_open())
                throw std::ofstream::failure::runtime_error("cannot open file!");
            file_descriptor << secret;
            file_descriptor.close();
            std::ifstream file_check(secret_path2.data(), std::ios::binary);
            if (!file_check.is_open())
                throw std::runtime_error("Cannot open file for secret store!");
            file_check.close();
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
     * Load secret from secret_filename if file name exists, or empty string is returned.
     * @param string_view_t& path to file
     * @returns string_t loaded secret, if any...
     *
     */
    __hint_load_secret_from_file__ const op_frame<string_t> load_secret_from_file(const string_view_t &secret_filename)
    {
        op_frame<string_t> return_block{.result{}, .error{.error_msg{}, .has_error{true}}};
        try
        {
            std::ifstream file_descriptor(secret_filename.data(), std::ios::binary);
            if (!file_descriptor.is_open())
                throw std::runtime_error("cannot open file for secret loading!");
            string_t buffer_bytes;
            file_descriptor.seekg(0, std::ios::end);
            const std::size_t fsecret_size(((std::size_t)file_descriptor.tellg() < (std::size_t)UINT64_MAX) ? ((std::size_t)file_descriptor.tellg()) : (std::size_t)0);
            file_descriptor.seekg(0, std::ios::beg);
            if (fsecret_size <= 0)
                throw std::runtime_error("secret file content empty!");
            buffer_bytes.resize(fsecret_size);
            do
            {
                return_block.result += buffer_bytes;
            } while (std::getline(file_descriptor, buffer_bytes));
            file_descriptor.close();
            buffer_bytes.clear();
            if (return_block.result.empty())
                throw std::runtime_error("collected 0 bytes from secret file address!");
            return_block.error.has_error = false;
        }
        catch (const std::exception &e)
        {
            return_block.error.has_error = true;
            return_block.error.error_msg = e.what();
        }
        return return_block;
    };

    ~ByteCrypt() {};

  private:

    __hint_rsa_key_pair_verify__ const bool __rsa_key_pair_verify(const rsa_key_pair_struct &key_block)
    {
        if (!key_block.public_key.has_value() || !key_block.private_key.has_value()) [[unlikely]]
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
            if (rsa_private_key.GetModulus() != rsa_public_key.GetModulus()) [[unlikely]]
                throw std::runtime_error("RSA Modulus Error!");
            public_key_byte_size = rsa_public_key.GetModulus().ByteCount();
            private_key_byte_size = rsa_private_key.GetModulus().ByteCount();
            if (private_key_byte_size != public_key_byte_size) [[unlikely]]
                throw std::runtime_error("RSA Byte Count error!");
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Rsa Key Verification: " << e.what() << "\n";
        }
        return false;
    };

    __hint_rsa_key_pem_set_header__ inline void __rsa_key_pem_set_header(string_t &rsa_key_var, const bool is_public_key) const noexcept
    {
        rsa_key_var.clear();
        if (is_public_key)
            rsa_key_var = RSA_PUBLIC_KEY_HEADER;
        else
            rsa_key_var = RSA_PRIVATE_KEY_HEADER;
    };

    __hint_rsa_key_pem_set_footer__ inline void __rsa_key_pem_set_footer(string_t &rsa_key_var, const bool is_public_key) const noexcept
    {
        if (rsa_key_var.empty())
            return;
        if (is_public_key)
            rsa_key_var += RSA_PUBLIC_KEY_FOOTER;
        else
            rsa_key_var += RSA_PRIVATE_KEY_FOOTER;
    };

    __hint_is_rsa_key_size_valid__ inline constexpr bool __is_rsa_key_size_valid(const std::size_t &key_size) const noexcept
    {
        for (std::uint8_t ksi = 0; ksi < rsa_key_size_options.size(); ksi++)
        {
            if ((std::size_t)rsa_key_size_options[ksi] == key_size) [[likely]]
            {
                return true;
            }
        }
        return false;
    };

    __hint_is_rsa_key_pem__ inline const bool __is_rsa_key_pem(const string_view_t &rsa_key, const e_rsa_key_pem_version version) noexcept
    {
        if (version == e_rsa_key_pem_version::PUBLIC)
        {
            if (!rsa_key.empty() && (rsa_key.find(RSA_PUBLIC_KEY_FOOTER) != std::string::npos && rsa_key.find(RSA_PUBLIC_KEY_HEADER) != std::string::npos)) [[likely]]
            {
                return true;
            }
        }
        else if (version == e_rsa_key_pem_version::PRIVATE)
        {
            if (!rsa_key.empty() && (rsa_key.find(RSA_PRIVATE_KEY_FOOTER) != std::string::npos && rsa_key.find(RSA_PRIVATE_KEY_HEADER) != std::string::npos)) [[likely]]
            {
                return true;
            }
        }
        return false;
    };

    __hint_is_rsa_encrypted_key__ inline const bool __is_rsa_encrypted_key(const string_view_t &rsa_key) noexcept
    {
        if (rsa_key.find(RSA_ENCRYPTED_PRIVATE_KEY_HEADER) != std::string::npos) [[likely]]
            return true;
        return false;
    };

    __hint_rsa_key_meta_wipe__ const string_t __rsa_key_meta_wipe(string_t &&rsa_key)
    {
        if (this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PRIVATE))
        {
            string_t wipe_rsa_meta(rsa_key.c_str());
            wipe_rsa_meta.erase(0, std::strlen(RSA_PRIVATE_KEY_HEADER));
            wipe_rsa_meta.erase(wipe_rsa_meta.find(RSA_PRIVATE_KEY_FOOTER), std::strlen(RSA_PRIVATE_KEY_FOOTER));
            std::size_t expected_rsa_key_size(rsa_key.length() - (std::strlen(RSA_PRIVATE_KEY_HEADER) + std::strlen(RSA_PRIVATE_KEY_FOOTER)));
            if (wipe_rsa_meta.length() == expected_rsa_key_size) [[likely]]
            {
                return wipe_rsa_meta;
            }
        }
        else if (this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PUBLIC))
        {
            string_t wipe_rsa_meta(rsa_key.c_str());
            wipe_rsa_meta.erase(0, std::strlen(RSA_PUBLIC_KEY_HEADER));
            wipe_rsa_meta.erase(wipe_rsa_meta.find(RSA_PUBLIC_KEY_FOOTER), std::strlen(RSA_PUBLIC_KEY_FOOTER));
            std::size_t expected_rsa_key_size(rsa_key.length() - (std::strlen(RSA_PUBLIC_KEY_HEADER) + std::strlen(RSA_PUBLIC_KEY_FOOTER)));
            if (wipe_rsa_meta.length() == expected_rsa_key_size) [[likely]]
            {
                return wipe_rsa_meta;
            }
        }
        return rsa_key;
    };

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