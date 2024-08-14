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
 *
 * ============================================================================
 *
 * Written by [Somorpher], [2024].
 */
// Platform detection

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32) || defined(_WIN64) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__sun) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(__ANDROID__) || defined(__unix__) ||   \
    defined(__HAIKU__)

// Architecture detection
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__M_X64) || defined(__aarch64__) || defined(__arm__) || defined(__powerpc64__) || defined(__ppc64__) || defined(__powerpc__) || defined(__ppc__) || defined(__sparc__) || defined(__mips__) || defined(__mips64__) || defined(__s390__) ||       \
    defined(__s390x__) || defined(__riscv) || defined(__riscv64__)

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__) || defined(_MSC_VER)

#if defined(_WIN32) || defined(_WIN64)
#define PATH_SEPARATOR "\\"
#include <windows.h>
#else
#define PATH_SEPARATOR "/"
#endif

#include <assert.h>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <errno.h>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
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
#include <crypto++/rsa.h>
#include <crypto++/seal.h>
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

#define DEFAULT_CIPHER_ITERATION_COUNTER 10000
#define DEFAULT_SEC_BLOCK_KEY_SIZE CryptoPP::AES::DEFAULT_KEYLENGTH
#define DEFAULT_SEC_BLOCK_IV_SIZE CryptoPP::AES::BLOCKSIZE

// makes code more readable instead of using inline attributes directly with function defintion

/*                      Attribution                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)

#define __hint_set_iter_counter__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_set_def_key_size__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_set_def_iv_size__ __attribute__((cold, nothrow, noipa, no_stack_protector))
#define __hint_encryption_algo_accept__ __attribute__((cold, nothrow, warn_unused_result, pure, no_sanitize_address, no_stack_protector, optimize(3)))
#define __hint_hash__ __attribute__((stack_protect, zero_call_used_regs("all"), warn_unused_result, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __hint_encrypt__ __attribute__((warn_unused_result, zero_call_used_regs("used"), stack_protect, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __hint_decrypt__ __attribute__((warn_unused_result, zero_call_used_regs("used"), stack_protect, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __hint_base64_encode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_base64_decode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_hex_encode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_hex_decode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_generate_rsa_key_der_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_generate_rsa_key_pem_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_sign_message__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), access(read_only, 2), zero_call_used_regs("used"), optimize("3")))
#define __hint_verify_signature__ __attribute__((warn_unused_result, access(read_only, 1), access(read_only, 2), access(read_only, 3), stack_protect, zero_call_used_regs("used"), optimize("3")))
#define __hint_save_rsa_key__ __attribute__((stack_protect, zero_call_used_regs("used"), tainted_args, access(read_only, 1), access(read_only, 2), optimize("3")))
#define __hint_load_rsa_key__ __attribute__((warn_unused_result, cold, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_derive_key_iv__ __attribute__((stack_protect, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), access(read_only, 3), optimize("1")))
#define __hint_perform_keyiv_intersection__ __attribute__((stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_rsa_key_pair_verify__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_rsa_key_pem_set_header__ __attribute__((nothrow, always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_rsa_key_pem_set_footer__ __attribute__((always_inline, nothrow, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("3")))
#define __hint_is_rsa_key_size_valid__ __attribute__((nothrow, warn_unused_result, always_inline, const, no_stack_protector, access(read_only, 1), optimize("1")))
#define __hint_is_rsa_key_pem__ __attribute__((warn_unused_result, nothrow, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("1")))
#define __hint_is_rsa_encrypted_key__ __attribute__((nothrow, warn_unused_result, const, always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize("0")))
#define __hint_rsa_key_meta_wipe__ __attribute__((const, zero_call_used_regs("used"), warn_unused_result, access(read_only, 1), optimize("2")))
#define __hint_generate_random_bytes__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), optimize("3")))
#define __hint_store_secret__ __attribute__((cold, stack_protect, optimize("3"), zero_call_used_regs("used"), access(read_only, 1)))
#define __hint_load_secret_from_file__ __attribute__((cold, warn_unused_result, stack_protect, optimize("3"), zero_call_used_regs("used"), access(read_only, 1)))
#define __hint_prepare_secure_keys__ __attribute__((stack_protect, zero_call_used_regs("all"), access(read_only, 1), optimize("3")))

#else

#define __hint_set_iter_counter__ [[nothrow]]
#define __hint_set_def_key_size__ [[nothrow]]
#define __hint_set_def_iv_size__ [[nothrow]]
#define __hint_encryption_algo_accept__ [[nothrow, nodiscard]]
#define __hint_hash__ [[nodiscard]]
#define __hint_encrypt__ [[nodiscard]]
#define __hint_decrypt__ [[nodiscard]]
#define __hint_base64_encode__ [[nodiscard]]
#define __hint_base64_decode__ [[nodiscard]]
#define __hint_hex_encode__ [[nodiscard]]
#define __hint_hex_decode__ [[nodiscard]]
#define __hint_generate_rsa_key_der_pair__ [[nodiscard]]
#define __hint_generate_rsa_key_der_pair__ [[nodiscard]]
#define __hint_sign_message__ [[nodiscard]]
#define __hint_verify_signature__ [[nodiscard]]
#define __hint_save_rsa_key__ [[nodiscard]]
#define __hint_load_rsa_key__ [[nodiscard]]
#define __hint_derive_key_iv__ [[]]
#define __hint_perform_keyiv_intersection__ [[]]
#define __hint_rsa_key_pair_verify__ [[nodiscard]]
#define __hint_rsa_key_pem_set_header__ [[nothrow]]
#define __hint_rsa_key_pem_set_footer__ [[nothrow]]
#define __hint_is_rsa_key_size_valid__ [[nothrow, nodiscard]]
#define __hint_is_rsa_key_pem__ [[nothrow, nodiscard]]
#define __hint_is_rsa_encrypted_key__ [[nothrow, nodiscard]]
#define __hint_rsa_key_meta_wipe__ [[nodiscard]]
#define __hint_generate_random_bytes__ [[warn_unused_result]]
#define __hint_store_secret__ [[nodiscard]]
#define __hint_load_secret_from_file__ [[nodiscard]]
#define __hint_prepare_secure_keys__ [[]]

#endif

#define __temp_perform_encryption__ template <typename encryptionType>
#define __temp_perform_decryption__ template <typename decryptionType>
#define __temp_byte_crypt__ template <typename std::size_t key_size_t = e_key_block_size::AES, typename std::size_t iv_size_t = e_iv_block_size::AES>

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

enum class e_rsa_key_pem_version
{
    PUBLIC = 0,
    PRIVATE
};

enum class e_operation_mode
{
    CBC = 0,
    GCM,
    EAX
};

enum class e_cbc_algorithm
{
    AES = 0,
    BLOWFISH,
    TWOFISH,
    CAST128,
    CAST256,
    IDEA,
    RC2,
    RC5,
    RC6,
    MARS,
    SERPENT,
    GOST,
    SPECK128,
    SIMON128,
    HIGHT,
    ARIA,
    SEED,
    __COUNT
};

enum class e_gcm_algorithm
{
    AES = 0,
    TWOFISH,
    RC6,
    MARS,
    __COUNT,
};

enum class e_eax_algorithm
{
    AES = 0,
    BLOWFISH,
    TWOFISH,
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

// struct but not regular purpose... goes here...
struct e_key_block_size
{
    static const std::size_t AES = CryptoPP::AES::DEFAULT_KEYLENGTH, BLOWFISH = CryptoPP::Blowfish::DEFAULT_KEYLENGTH, TWOFISH = CryptoPP::Twofish::DEFAULT_KEYLENGTH, CAST128 = CryptoPP::CAST128::DEFAULT_KEYLENGTH, CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH, IDEA = CryptoPP::IDEA::DEFAULT_KEYLENGTH,
                             RC2 = CryptoPP::RC2::DEFAULT_KEYLENGTH, RC5 = CryptoPP::RC5::DEFAULT_KEYLENGTH, RC6 = CryptoPP::RC6::DEFAULT_KEYLENGTH, MARS = CryptoPP::MARS::DEFAULT_KEYLENGTH, SERPENT = CryptoPP::Serpent::DEFAULT_KEYLENGTH, GOST = CryptoPP::GOST::DEFAULT_KEYLENGTH, ARIA = CryptoPP::ARIA::BLOCKSIZE,
                             HIGHT = CryptoPP::HIGHT::BLOCKSIZE, LEA = CryptoPP::LEA::DEFAULT_KEYLENGTH, SEED = CryptoPP::GOST::DEFAULT_KEYLENGTH, SPECK128 = CryptoPP::SPECK128::DEFAULT_KEYLENGTH, SIMON128 = CryptoPP::SIMON128::DEFAULT_KEYLENGTH;
};

struct e_iv_block_size
{
    static const std::size_t AES = CryptoPP::AES::BLOCKSIZE, BLOWFISH = CryptoPP::Blowfish::BLOCKSIZE, TWOFISH = CryptoPP::Twofish::BLOCKSIZE, CAST128 = CryptoPP::CAST128::BLOCKSIZE, CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH, IDEA = CryptoPP::IDEA::BLOCKSIZE, RC2 = CryptoPP::RC2::BLOCKSIZE,
                             RC5 = CryptoPP::RC5::BLOCKSIZE, RC6 = CryptoPP::RC6::BLOCKSIZE, MARS = CryptoPP::MARS::BLOCKSIZE, SERPENT = CryptoPP::Serpent::BLOCKSIZE, GOST = CryptoPP::GOST::BLOCKSIZE, ARIA = CryptoPP::ARIA::BLOCKSIZE, HIGHT = CryptoPP::HIGHT::BLOCKSIZE, LEA = CryptoPP::LEA::BLOCKSIZE,
                             SEED = CryptoPP::GOST::BLOCKSIZE, SIMON128 = CryptoPP::SIMON128::BLOCKSIZE, SPECK128 = CryptoPP::SPECK128::BLOCKSIZE;
};

typedef struct e_key_block_size e_key_block_size_t;
typedef struct e_iv_block_size e_iv_block_size_t;

/*                      Type Alias                       *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
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
using sha256_hmac_t = CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>;
using hmac_s256_t = CryptoPP::HMAC<CryptoPP::SHA256>;
using auth_decryption_filter_t = CryptoPP::AuthenticatedDecryptionFilter;
using auth_encryption_filter_t = CryptoPP::AuthenticatedEncryptionFilter;
using sec_byte_block_t = CryptoPP::SecByteBlock;

/**
 * CBC Mode Encryption/Dec(< GCM)
 */

using cbc_aes_encryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Encryption;
using cbc_blowfish_encryption_t = CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption;
using cbc_twofish_encryption_t = CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption;
using cbc_cast128_encryption_t = CryptoPP::CBC_Mode<CryptoPP::CAST128>::Encryption;
using cbc_cast256_encryption_t = CryptoPP::CBC_Mode<CryptoPP::CAST256>::Encryption;
using cbc_idea_encryption_t = CryptoPP::CBC_Mode<CryptoPP::IDEA>::Encryption;
using cbc_rc2_encryption_t = CryptoPP::CBC_Mode<CryptoPP::RC2>::Encryption;
using cbc_rc5_encryption_t = CryptoPP::CBC_Mode<CryptoPP::RC5>::Encryption;
using cbc_rc6_encryption_t = CryptoPP::CBC_Mode<CryptoPP::RC6>::Encryption;
using cbc_mars_encryption_t = CryptoPP::CBC_Mode<CryptoPP::MARS>::Encryption;
using cbc_serpent_encryption_t = CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption;
using cbc_gost_encryption_t = CryptoPP::CBC_Mode<CryptoPP::GOST>::Encryption;
using cbc_aria_encryption_t = CryptoPP::CBC_Mode<CryptoPP::ARIA>::Encryption;
using cbc_simon128_encryption_t = CryptoPP::CBC_Mode<CryptoPP::SIMON128>::Encryption;
using cbc_speck128_encryption_t = CryptoPP::CBC_Mode<CryptoPP::SPECK128>::Encryption;
using cbc_hight_encryption_t = CryptoPP::CBC_Mode<CryptoPP::HIGHT>::Encryption;
using cbc_seed_encryption_t = CryptoPP::CBC_Mode<CryptoPP::SEED>::Encryption;

using cbc_aes_decryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Decryption;
using cbc_blowfish_decryption_t = CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption;
using cbc_twofish_decryption_t = CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption;
using cbc_cast128_decryption_t = CryptoPP::CBC_Mode<CryptoPP::CAST128>::Decryption;
using cbc_cast256_decryption_t = CryptoPP::CBC_Mode<CryptoPP::CAST256>::Decryption;
using cbc_idea_decryption_t = CryptoPP::CBC_Mode<CryptoPP::IDEA>::Decryption;
using cbc_rc2_decryption_t = CryptoPP::CBC_Mode<CryptoPP::RC2>::Decryption;
using cbc_rc5_decryption_t = CryptoPP::CBC_Mode<CryptoPP::RC5>::Decryption;
using cbc_rc6_decryption_t = CryptoPP::CBC_Mode<CryptoPP::RC6>::Decryption;
using cbc_mars_decryption_t = CryptoPP::CBC_Mode<CryptoPP::MARS>::Decryption;
using cbc_serpent_decryption_t = CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption;
using cbc_gost_decryption_t = CryptoPP::CBC_Mode<CryptoPP::GOST>::Decryption;
using cbc_aria_decryption_t = CryptoPP::CBC_Mode<CryptoPP::ARIA>::Decryption;
using cbc_simon128_decryption_t = CryptoPP::CBC_Mode<CryptoPP::SIMON128>::Decryption;
using cbc_speck128_decryption_t = CryptoPP::CBC_Mode<CryptoPP::SPECK128>::Decryption;
using cbc_hight_decryption_t = CryptoPP::CBC_Mode<CryptoPP::HIGHT>::Decryption;
using cbc_seed_decryption_t = CryptoPP::CBC_Mode<CryptoPP::SEED>::Decryption;

/**
 * GCM Mode Encryption/Dec(> CBC)
 */
using gcm_aes_encryption_t = CryptoPP::GCM<cbc_cipher_t>::Encryption;
using gcm_twofish_encryption_t = CryptoPP::GCM<CryptoPP::Twofish>::Encryption;
using gcm_rc6_encryption_t = CryptoPP::GCM<CryptoPP::RC6>::Encryption;
using gcm_mars_encryption_t = CryptoPP::GCM<CryptoPP::MARS>::Encryption;

using gcm_aes_decryption_t = CryptoPP::GCM<cbc_cipher_t>::Decryption;
using gcm_twofish_decryption_t = CryptoPP::GCM<CryptoPP::Twofish>::Decryption;
using gcm_rc6_decryption_t = CryptoPP::GCM<CryptoPP::RC6>::Decryption;
using gcm_mars_decryption_t = CryptoPP::GCM<CryptoPP::MARS>::Decryption;

using eax_aes_encryption_t = CryptoPP::EAX<CryptoPP::AES>::Encryption;
using eax_blowfish_encryption_t = CryptoPP::EAX<CryptoPP::Blowfish>::Encryption;
using eax_twofish_encryption_t = CryptoPP::EAX<CryptoPP::Twofish>::Encryption;
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
using eax_twofish_decryption_t = CryptoPP::EAX<CryptoPP::Twofish>::Decryption;
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

/*                      Type Traits                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

// CBC Mode of Operation
template <typename mT> __hint_encryption_algo_accept__ static constexpr bool cbc_encryption_algo_accept()
{
    return std::is_same_v<mT, cbc_aes_encryption_t> || std::is_same_v<mT, cbc_blowfish_encryption_t> || std::is_same_v<mT, cbc_twofish_encryption_t> || std::is_same_v<mT, cbc_cast128_encryption_t> || std::is_same_v<mT, cbc_cast256_encryption_t> || std::is_same_v<mT, cbc_idea_encryption_t> ||
           std::is_same_v<mT, cbc_rc2_encryption_t> || std::is_same_v<mT, cbc_rc5_encryption_t> || std::is_same_v<mT, cbc_rc6_encryption_t> || std::is_same_v<mT, cbc_mars_encryption_t> || std::is_same_v<mT, cbc_aes_decryption_t> || std::is_same_v<mT, cbc_blowfish_decryption_t> ||
           std::is_same_v<mT, cbc_twofish_decryption_t> || std::is_same_v<mT, cbc_cast128_decryption_t> || std::is_same_v<mT, cbc_cast256_decryption_t> || std::is_same_v<mT, cbc_idea_decryption_t> || std::is_same_v<mT, cbc_rc2_decryption_t> || std::is_same_v<mT, cbc_rc5_decryption_t> ||
           std::is_same_v<mT, cbc_rc6_decryption_t> || std::is_same_v<mT, cbc_mars_decryption_t> || std::is_same_v<mT, cbc_serpent_encryption_t> || std::is_same_v<mT, cbc_gost_encryption_t> || std::is_same_v<mT, cbc_serpent_decryption_t> || std::is_same_v<mT, cbc_gost_decryption_t> ||
           std::is_same_v<mT, cbc_aria_decryption_t> || std::is_same_v<mT, cbc_aria_encryption_t> || std::is_same_v<mT, cbc_seed_decryption_t> || std::is_same_v<mT, cbc_gost_encryption_t> || std::is_same_v<mT, cbc_simon128_encryption_t> || std::is_same_v<mT, cbc_simon128_decryption_t> ||
           std::is_same_v<mT, cbc_hight_encryption_t> || std::is_same_v<mT, cbc_hight_decryption_t> || std::is_same_v<mT, cbc_speck128_encryption_t> || std::is_same_v<mT, cbc_speck128_decryption_t> || std::is_same_v<mT, cbc_seed_encryption_t> || std::is_same_v<mT, cbc_seed_decryption_t>;
};
template <typename mT> struct is_accepted_cbc_encryption_algorithm
{
    static constexpr bool value = cbc_encryption_algo_accept<mT>();
};
template <typename mT> constexpr bool is_accepted_cbc_encryption_algorithm_v = is_accepted_cbc_encryption_algorithm<mT>::value;

// GCM Mode of Operation
template <typename mT> __hint_encryption_algo_accept__ static constexpr bool gcm_encryption_algo_accept()
{
    return std::is_same_v<mT, gcm_aes_encryption_t> || std::is_same_v<mT, gcm_twofish_encryption_t> || std::is_same_v<mT, gcm_rc6_encryption_t> || std::is_same_v<mT, gcm_mars_encryption_t> || std::is_same_v<mT, gcm_aes_decryption_t> || std::is_same_v<mT, gcm_twofish_decryption_t> ||
           std::is_same_v<mT, gcm_rc6_decryption_t> || std::is_same_v<mT, gcm_mars_decryption_t>;
};
template <typename mT> struct is_accepted_gcm_encryption_algorithm
{
    static constexpr bool value = gcm_encryption_algo_accept<mT>();
};
template <typename mT> constexpr bool is_accepted_gcm_encryption_algorithm_v = is_accepted_gcm_encryption_algorithm<mT>::value;

// EAX Mode of Operation
template <typename mT> __hint_encryption_algo_accept__ static constexpr bool eax_encryption_algo_accept()
{
    return std::is_same_v<mT, eax_aes_encryption_t> || std::is_same_v<mT, eax_blowfish_encryption_t> || std::is_same_v<mT, eax_twofish_encryption_t> || std::is_same_v<mT, eax_serpent_encryption_t> || std::is_same_v<mT, eax_cast128_encryption_t> || std::is_same_v<mT, eax_cast256_encryption_t> ||
           std::is_same_v<mT, eax_idea_encryption_t> || std::is_same_v<mT, eax_rc5_encryption_t> || std::is_same_v<mT, eax_rc6_encryption_t> || std::is_same_v<mT, eax_gost_encryption_t> || std::is_same_v<mT, eax_mars_encryption_t> || std::is_same_v<mT, eax_seed_encryption_t> ||
           std::is_same_v<mT, eax_speck128_encryption_t> || std::is_same_v<mT, eax_lea_encryption_t> || std::is_same_v<mT, eax_aes_decryption_t> || std::is_same_v<mT, eax_blowfish_decryption_t> || std::is_same_v<mT, eax_twofish_decryption_t> || std::is_same_v<mT, eax_serpent_decryption_t> ||
           std::is_same_v<mT, eax_cast128_decryption_t> || std::is_same_v<mT, eax_cast256_decryption_t> || std::is_same_v<mT, eax_idea_decryption_t> || std::is_same_v<mT, eax_rc5_decryption_t> || std::is_same_v<mT, eax_rc6_decryption_t> || std::is_same_v<mT, eax_gost_decryption_t> ||
           std::is_same_v<mT, eax_mars_decryption_t> || std::is_same_v<mT, eax_seed_decryption_t> || std::is_same_v<mT, eax_speck128_decryption_t> || std::is_same_v<mT, eax_lea_decryption_t> || std::is_same_v<mT, eax_simon128_encryption_t> || std::is_same_v<mT, eax_simon128_decryption_t> ||
           std::is_same_v<mT, eax_hight_encryption_t> || std::is_same_v<mT, eax_hight_decryption_t>;
}
template <typename mT> struct is_accepted_eax_encryption_algorithm
{
    static constexpr bool value = eax_encryption_algo_accept<mT>();
};
template <typename mT> constexpr bool is_accepted_eax_encryption_algorithm_v = is_accepted_eax_encryption_algorithm<mT>::value;

#define __temp_encrypt__ template <e_operation_mode op_mode_t = e_operation_mode::CBC, e_cbc_algorithm algorithm_t = e_cbc_algorithm::AES>
#define __temp_decrypt__ template <e_operation_mode op_mode_t = e_operation_mode::CBC, e_cbc_algorithm algorithm_t = e_cbc_algorithm::AES>
#define __temp_prepare_secure_keys__ template <e_operation_mode op_mode_t, e_cbc_algorithm algorithm_t>

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
    string_t error_msg{};
    bool has_error{false};
} error_frame;

typedef struct alignas(void *)
{
    sec_byte_block_t key;
    sec_byte_block_t iv;
} secure_byte_pair;

typedef struct alignas(void *)
{
    string_t encrypted_block;
    error_frame error;
    secure_byte_pair secure_keys;
} encryption_result;

typedef struct alignas(void *)
{
    string_t decrypted_block;
    error_frame error;
    secure_byte_pair secure_keys;
} decryption_result;

typedef struct alignas(void *)
{
    int secure_key{};
    int secure_ivector{};
} mode_of_operation_map;

struct operation_mode
{
    std::unordered_map<e_cbc_algorithm, mode_of_operation_map> cbc{
        {e_cbc_algorithm::AES, mode_of_operation_map{.secure_key{e_key_block_size::AES}, .secure_ivector{e_iv_block_size::AES}}},
        {e_cbc_algorithm::ARIA, mode_of_operation_map{.secure_key{e_key_block_size::ARIA}, .secure_ivector{e_iv_block_size::ARIA}}},
        {e_cbc_algorithm::BLOWFISH, mode_of_operation_map{.secure_key{e_key_block_size::BLOWFISH}, .secure_ivector{e_iv_block_size::BLOWFISH}}},
        {e_cbc_algorithm::CAST128, mode_of_operation_map{.secure_key{e_key_block_size::CAST128}, .secure_ivector{e_iv_block_size::CAST128}}},
        {e_cbc_algorithm::CAST256, mode_of_operation_map{.secure_key{e_key_block_size::CAST256}, .secure_ivector{e_iv_block_size::CAST256}}},
        {e_cbc_algorithm::GOST, mode_of_operation_map{.secure_key{e_key_block_size::GOST}, .secure_ivector{e_iv_block_size::GOST}}},
        {e_cbc_algorithm::HIGHT, mode_of_operation_map{.secure_key{e_key_block_size::HIGHT}, .secure_ivector{e_iv_block_size::HIGHT}}},
        {e_cbc_algorithm::IDEA, mode_of_operation_map{.secure_key{e_key_block_size::IDEA}, .secure_ivector{e_iv_block_size::IDEA}}},
        {e_cbc_algorithm::MARS, mode_of_operation_map{.secure_key{e_key_block_size::MARS}, .secure_ivector{e_iv_block_size::MARS}}},
        {e_cbc_algorithm::RC2, mode_of_operation_map{.secure_key{e_key_block_size::RC2}, .secure_ivector{e_iv_block_size::RC2}}},
        {e_cbc_algorithm::RC5, mode_of_operation_map{.secure_key{e_key_block_size::RC5}, .secure_ivector{e_iv_block_size::RC5}}},
        {e_cbc_algorithm::RC6, mode_of_operation_map{.secure_key{e_key_block_size::RC6}, .secure_ivector{e_iv_block_size::RC6}}},
        {e_cbc_algorithm::SEED, mode_of_operation_map{.secure_key{e_key_block_size::SEED}, .secure_ivector{e_iv_block_size::SEED}}},
        {e_cbc_algorithm::SERPENT, mode_of_operation_map{.secure_key{e_key_block_size::SERPENT}, .secure_ivector{e_iv_block_size::SERPENT}}},
        {e_cbc_algorithm::SIMON128, mode_of_operation_map{.secure_key{e_key_block_size::SIMON128}, .secure_ivector{e_iv_block_size::SIMON128}}},
        {e_cbc_algorithm::SPECK128, mode_of_operation_map{.secure_key{e_key_block_size::SPECK128}, .secure_ivector{e_iv_block_size::SPECK128}}},
        {e_cbc_algorithm::TWOFISH, mode_of_operation_map{.secure_key{e_key_block_size::TWOFISH}, .secure_ivector{e_iv_block_size::TWOFISH}}},
    };
    std::unordered_map<e_gcm_algorithm, mode_of_operation_map> gcm{{e_gcm_algorithm::AES, mode_of_operation_map{.secure_key{e_key_block_size::AES}, .secure_ivector{e_iv_block_size::AES}}},
                                                                   {e_gcm_algorithm::MARS, mode_of_operation_map{.secure_key{e_key_block_size::MARS}, .secure_ivector{e_iv_block_size::MARS}}},
                                                                   {e_gcm_algorithm::RC6, mode_of_operation_map{.secure_key{e_key_block_size::RC6}, .secure_ivector{e_iv_block_size::RC6}}},
                                                                   {e_gcm_algorithm::TWOFISH, mode_of_operation_map{.secure_key{e_key_block_size::TWOFISH}, .secure_ivector{e_iv_block_size::TWOFISH}}}};
    std::unordered_map<e_eax_algorithm, mode_of_operation_map> eax{
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
        {e_eax_algorithm::TWOFISH, mode_of_operation_map{.secure_key{e_key_block_size::TWOFISH}, .secure_ivector{e_iv_block_size::TWOFISH}}},
    };
};

/*                      Class                            *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
__temp_byte_crypt__ class ByteCrypt
{
    std::unique_ptr<string_t> secret_key = std::make_unique<string_t>();
    std::uint16_t cipher_iteration_count = DEFAULT_CIPHER_ITERATION_COUNTER;
    std::uint16_t default_sec_key_size = DEFAULT_SEC_BLOCK_KEY_SIZE;
    std::uint16_t default_sec_iv_size = DEFAULT_SEC_BLOCK_IV_SIZE;
    static constexpr std::array<std::uint16_t, 5> rsa_key_size_options{512u, 1024u, 2048u, 3072u, 4096u};
    operation_mode op_mode;

  public:
    inline ByteCrypt() noexcept {};

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
        if (key_size == std::size(this->__key__))
            for (std::uint16_t j{0}; j < key_size; ++j)
                this->__key__[j] = key[j];
        if (iv_size == std::size(this->__iv__))
            for (std::uint16_t j{0}; j < iv_size; ++j)
                this->__iv__[j] = iv[j];
    };

    inline const bool operator==(const ByteCrypt &o_instance) const noexcept
    {
        return this->secret_key.get()->compare(o_instance.secret_key.get()->c_str()) == 0;
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
     * @param std::size_t key size
     * @returns void
     *
     */
    __hint_set_def_key_size__ inline void set_sec_block_key_size(const std::size_t key_size) noexcept
    {
        if (key_size >= 8 && key_size <= 256)
        {
            this->default_sec_key_size = key_size;
        }
    };

    /**
     *
     * Set default secure initialization vector size.
     * @param std::size_t initialization vector size
     * @returns void
     *
     */
    __hint_set_def_iv_size__ inline void set_sec_block_iv_size(const std::size_t iv_size) noexcept
    {
        if (iv_size >= 8 && iv_size <= 256)
        {
            this->default_sec_iv_size = iv_size;
        }
    };

    /**
     * Hash buffer with sha algorithm and return hashed result.
     * @param string_t& buffer to hash
     * @param e_hash_algo_option hash algorithm
     * @returns string_t const string hash buffer
     */
    __hint_hash__ const string_t hash(const string_t &buffer, const e_hash_algo_option sha = e_hash_algo_option::SHA256) const
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

    /**
     * base64 encoding of plain_text buffer
     * @param string_t& data to encode using base64 encoding
     * @returns string_t encoded data
     */
    __hint_base64_encode__ inline const string_t base64_encode(const string_t &plain_text)
    {
        string_t b64_encoded;
        CryptoPP::StringSource(plain_text, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(b64_encoded)));
        return b64_encoded;
    };

    /**
     * decode encoded_cipher using base64.
     * @param string_t& encoded cipher to decode
     * @returns string_t base64 decoded data
     */
    __hint_base64_decode__ inline const string_t base64_decode(const string_t &encoded_cipher)
    {
        string_t b64_decoded;
        CryptoPP::StringSource(encoded_cipher, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(b64_decoded)));
        return b64_decoded;
    };

    /**
     * encode plain_text with hex
     * @param string_t& data to encode
     * @returns string_t hex encoded data
     */
    __hint_hex_encode__ inline const string_t hex_encode(const string_t &plain_text)
    {
        std::ostringstream parser;
        for (unsigned char _byte : plain_text)
            parser << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_byte);
        return parser.str();
    };

    /**
     * decode hex_encoded data
     * @param string_t& hex encoded data
     * @returns string_t hex decoded data
     */
    __hint_hex_decode__ inline const string_t hex_decode(const string_t &hex_encoded)
    {
        if (hex_encoded.length() % 2 != 0) [[unlikely]]
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

    /**
     * generate a pair of DER RSA keys with rsa_key_size size, size defaults to 2048 bits.
     * @param std::size_t rsa key size
     * @returns rsa_key_pair_struct structure with public and private key association
     */
    __hint_generate_rsa_key_der_pair__ const rsa_key_pair_struct generate_rsa_key_der_pair(const std::size_t rsa_key_size = 2048U)
    {
        rsa_key_pair_struct local_kps{};
        if (!this->__is_rsa_key_size_valid(rsa_key_size)) [[unlikely]]
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

            if (!private_key_result.empty()) [[likely]]
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
                    if (!private_key_result.empty()) [[likely]]
                        private_key_result.clear();
                }
            }
            if (!private_key_result_encoded.empty() && !public_key_result_encoded.empty()) [[likely]]
            {
                local_kps.private_key = std::move(private_key_result_encoded);
                local_kps.public_key = std::move(public_key_result_encoded);
                if (this->__rsa_key_pair_verify(local_kps)) [[likely]]
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

    /**
     * generate a pair of RSA PEM key pair with rsa_key_size size.
     * @param std::size_t rsa key size
     * @returns rsa_key_pair_struct structure with the rsa generated PEM keys.
     */
    __hint_generate_rsa_key_pem_pair__ const rsa_key_pair_struct generate_rsa_key_pem_pair(const std::size_t rsa_key_size = 2048U)
    {
        rsa_key_pair_struct rsa_keys = this->generate_rsa_key_der_pair(rsa_key_size);
        if (!this->__is_rsa_key_size_valid(rsa_key_size)) [[unlikely]]
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

    /**
     * sign message with rsa_key private key, function generates signature and returns it.
     * @param string_t& message to sign
     * @param string_t& rsa private key for signature generation
     * @returns string_t signature
     */
    __hint_sign_message__ const string_t sign_message(const string_t &message, const string_t &rsa_key)
    {
        string_t signature;
        if (!this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PRIVATE)) [[unlikely]]
            return signature;
        string_t clean_key(this->__rsa_key_meta_wipe(const_cast<string_t &&>(std::move(rsa_key))));
        try
        {
            if (clean_key.empty() || message.empty()) [[unlikely]]
                return signature;

            string_t private_key_decoded;
            string_source_t(clean_key, true, new base64_decoder_t(new string_sink_t(private_key_decoded)));
            rsa_private_key_t private_key;
            string_source_t private_key_source(private_key_decoded, true);
            private_key.BERDecode(private_key_source);
            rsa_signature_t signer(private_key);
            entropy_seed_t entropy;
            string_source_t(message, true, new rsa_signature_filter_t(entropy, signer, new string_sink_t(signature)));
            string_t encoded_signature;
            string_source_t(signature, true, new base64_encoder_t(new string_sink_t(encoded_signature)));
            return encoded_signature;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Sign Error: " << e.what() << "\n";
            return "";
        }
    };

    /**
     * verify message rsa private key signature with signature_str signature, and rsa_key public key
     * @param string_t& message to verify signature from
     * @param string_t& signature to use
     * @param string_t& RSA public key
     * @returns bool true if verification succeded
     */
    __hint_verify_signature__ const bool verify_signature(const string_t &message, const string_t &signature_str, const string_t &rsa_key)
    {
        if (!this->__is_rsa_key_pem(rsa_key, e_rsa_key_pem_version::PUBLIC)) [[unlikely]]
            return false;
        try
        {
            string_t public_key_decoded;
            string_t pure_key(this->__rsa_key_meta_wipe(const_cast<string_t &&>(std::move(rsa_key))));
            string_source_t(pure_key, true, new base64_decoder_t(new string_sink_t(public_key_decoded)));
            rsa_public_key_t public_key;
            string_source_t public_key_source(public_key_decoded, true);
            public_key.BERDecode(public_key_source);
            string_t signature_decoded;
            string_source_t(signature_str, true, new base64_decoder_t(new string_sink_t(signature_decoded)));
            rsa_signature_verify_t verifier(public_key);
            const bool result = verifier.VerifyMessage((const byte *)message.data(), message.size(), (const byte *)signature_decoded.data(), signature_decoded.size());
            return result;
        }
        catch (const crypto_exception_t &e)
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

    /**
     * save rsa_key into path(file name).
     * @param string_t& path to key
     * @param string_t& rsa key(public/private)
     * @returns bool true if key saved
     */
    __hint_save_rsa_key__ const bool save_rsa_key(const string_view_t &path, const string_t &rsa_key)
    {
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception: " << e.what() << "\n";
        }
        return false;
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
            {
                rsa_loader.key += read_key += "\n";
            } while (std::getline(file_handler, read_key));
            file_handler.close();
            if (!rsa_loader.key.empty()) [[likely]]
                rsa_loader.status = true;

            return rsa_loader;
        }
        catch (const std::exception &e)
        {
            rsa_loader.error = e.what();
        }
        return rsa_loader;
    };

    /**
     *
     * Generate Random Bytes using secure system entropy generator with 16 bytes output block size.
     * @returns string_t the random generated string
     *
     */
    __hint_generate_random_bytes__ const string_t generate_random_bytes(void)
    {
        string_t final_secret;
        try
        {
            entropy_seed_t entropy;
            byte random_bytes[16];
            entropy.GenerateBlock(random_bytes, sizeof(random_bytes));
            string_source_t(random_bytes, sizeof(random_bytes), true, new hex_encoder_t(new string_sink_t(final_secret)));
        }
        catch (const std::exception &e)
        {
            std::cerr << "SecretGenerate Error: " << e.what() << "\n";
            final_secret.clear();
        }
        return final_secret;
    };

    /**
     *
     * Store secret(K) within secret_path, if flag "hide" is true, this will preceed the destination file
     * with a "." so it hides it(kind of), default is false.
     * @param string_view_t& secret to store
     * @param string_t& path to store
     * @param bool if true it will hide the secret file name
     *
     */
    __hint_store_secret__ bool store_secret(const string_view_t &secret, string_t &secret_path, const bool hide = false) noexcept
    {
        if (secret.empty() || secret_path.empty())
            return false;
        try
        {
            if (hide)
            {
                string_t last_path_segment(secret_path.c_str());
                if (secret_path.find(PATH_SEPARATOR) != string_t::npos)
                {
                    last_path_segment = secret_path.substr(secret_path.find(PATH_SEPARATOR) + 1);
                }
                if (last_path_segment.find(".") != 0)
                {
                    last_path_segment = "." + last_path_segment;
                }
                secret_path = std::move(last_path_segment);
            }
            std::ofstream file_descriptor(secret_path, std::ios::binary);
            if (!file_descriptor.is_open())
                throw std::ofstream::failure::runtime_error("cannot open file!");
            file_descriptor << secret;
            file_descriptor.close();
            std::ifstream file_check(secret_path.c_str(), std::ios::binary);
            if (!file_check.is_open())
                return false;
            file_check.close();
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception: " << e.what() << "\n";
        }
        return false;
    };

    /**
     *
     * Load secret from secret_filename if file name exists, or empty string is returned.
     * @param string_view_t& path to file
     * @returns string_t loaded secret, if any...
     *
     */
    __hint_load_secret_from_file__ const string_t load_secret_from_file(const string_view_t &secret_filename)
    {
        string_t loaded_secret;
        try
        {
            std::basic_ifstream<char> file_descriptor(&secret_filename[0], std::ios::binary);
            if (!file_descriptor.is_open())
                throw std::ifstream::failure::runtime_error("cannot open file for secret loading!");
            string_t buffer_bytes;
            file_descriptor.seekg(0, std::ios::end);
            const std::size_t fsecret_size(file_descriptor.tellg());
            file_descriptor.seekg(0, std::ios::beg);
            buffer_bytes.resize(fsecret_size);
            do
            {
                loaded_secret += buffer_bytes;
            } while (std::getline(file_descriptor, buffer_bytes));
            file_descriptor.close();
            buffer_bytes.clear();
        }
        catch (const std::exception &e)
        {
            std::cerr << "LoadSecret Error: " << e.what() << '\n';
        }
        return loaded_secret;
    };

    /**
     *
     * Shift block to right by "shift_pos" positions, "shift_pos", shift_pos does not usually exceed values such as(100-200).
     * @param string_view_t& block to shift
     * @param int the number of positions to r-move
     * @returns string_t the right shifted block
     *
     */
    const string_t block_rshift(const string_view_t block, const short int shift_pos = 3)
    {
        if (block.empty())
            return "";
        string_t local_bytes;
        local_bytes.reserve(block.length());
        for (const char index_byte : block)
        {
            local_bytes += static_cast<char>((static_cast<int>(index_byte) + (shift_pos % 256)) % 256);
        }
        return local_bytes;
    }

    /**
     *
     * Shift block to left by "shift_pos" positions, "shift_pos", shift_pos does not usually exceed values such as(100-200).
     * @param string_view_t& block to shift
     * @param int the number of positions to l-move
     * @returns string_t the left shifted block
     *
     */
    const string_t block_lshift(const string_view_t block, const short int shift_pos = 3)
    {
        if (block.empty())
            return "";
        string_t local_bytes;
        local_bytes.reserve(block.length());
        for (const char index_byte : block)
        {
            local_bytes += static_cast<char>((static_cast<int>(index_byte) - (shift_pos % 256) + 256) % 256);
        }
        return local_bytes;
    };

    __temp_encrypt__ __hint_encrypt__ const encryption_result encrypt(const string_t &buffer, const string_t &secret)
    {
        encryption_result result;

        try
        {
            if (op_mode_t == e_operation_mode::CBC)
            {
                string_t target;
                entropy_seed_t ring;
                byte salt[16];
                ring.GenerateBlock(salt, sizeof(salt));
                sec_byte_block_t key, iv;
                this->__prepare_secure_keys<op_mode_t, algorithm_t>(secret, key, iv, salt, sizeof(salt));
                cbc_aes_encryption_t encryption;
                encryption.SetKeyWithIV(key, key.size(), iv);
                string_t r0;
                string_source_t(buffer, true, new transformer_filter_t(encryption, new string_sink_t(r0)));
                const string_t r2(string_t(reinterpret_cast<char *>(salt), sizeof(salt)) + r0);
                string_source_t(r2, true, new hex_encoder_t(new string_sink_t(target)));
                result.encrypted_block = std::move(target);
            }
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }

        return result;
    };

    __temp_decrypt__ __hint_decrypt__ const decryption_result decrypt(const string_t &buffer, const string_t &secret)
    {
        decryption_result result;
        try
        {
            if (op_mode_t == e_operation_mode::CBC)
            {
                string_t target;
                byte salt[16];
                string_t rd;
                string_source_t(buffer, true, new hex_decoder_t(new string_sink_t(rd)));
                memcpy(salt, rd.data(), sizeof(salt));
                string_t ciphertext(rd.substr(sizeof(salt)));
                sec_byte_block_t key, iv;
                this->__prepare_secure_keys<op_mode_t, algorithm_t>(secret, key, iv, salt, sizeof(salt));
                string_t r0;
                cbc_aes_decryption_t decryption;
                decryption.SetKeyWithIV(key, key.size(), iv);
                string_source_t(ciphertext, true, new transformer_filter_t(decryption, new string_sink_t(target)));
                result.decrypted_block = std::move(target);
            }
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    };

    ~ByteCrypt() {};

  private:
    __temp_prepare_secure_keys__ __hint_prepare_secure_keys__ inline void __prepare_secure_keys(const string_t &cipher, sec_byte_block_t &key, sec_byte_block_t &iv, const byte *salt, const std::size_t salt_size)
    {
        std::size_t key_size = this->default_sec_key_size, iv_size = this->default_sec_iv_size;
        if (op_mode_t == e_operation_mode::CBC)
        {
            sha256_hmac_t hmac;
            if (algorithm_t == e_cbc_algorithm::AES)
            {
                key_size = this->op_mode.cbc.at(e_cbc_algorithm::AES).secure_key;
                iv_size = this->op_mode.cbc.at(e_cbc_algorithm::AES).secure_ivector;
            }

            key.CleanNew(key_size);
            iv.CleanNew(iv_size);

            hmac.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
            hmac.DeriveKey(iv, iv.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
        }
    };

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

    __hint_is_rsa_key_size_valid__ constexpr bool __is_rsa_key_size_valid(const std::size_t &key_size) const noexcept
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

    __hint_is_rsa_key_pem__ const bool __is_rsa_key_pem(const string_view_t &rsa_key, const e_rsa_key_pem_version version) noexcept
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
        return std::move(rsa_key);
    };

    inline void __constructor_copy_handler(const ByteCrypt &o_instance) noexcept
    {
        if (*this != o_instance)
        {
            *this->secret_key = *o_instance.secret_key;
            this->cipher_iteration_count = o_instance.cipher_iteration_count;
            this->default_sec_iv_size = o_instance.default_sec_iv_size;
            this->default_sec_key_size = o_instance.default_sec_key_size;
            if (std::size(o_instance.__key__) > 0)
                for (std::uint16_t j{0}; j < std::size(o_instance.__key__); ++j)
                    this->__key__[j] = o_instance.__key__[j];
            if (std::size(o_instance.__iv__) == std::size(this->__iv__))
                for (std::uint16_t j{0}; j < std::size(o_instance.__iv__); ++j)
                    this->__iv__[j] = o_instance.__iv__[j];
        }
    };
};
}; // namespace ByteCryptModule
#endif

#endif

#endif

#endif
