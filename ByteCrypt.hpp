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

/**
 * Cryptographic Utility library for most common cryptograpic operations, algorithms, modes, etc...
 *
 * Symmetric Encryption:
 * Available Modes: CBC((16+-)algos), GCM((4+-)algos), EAX((15+-)algos)
 * Hashing: SHA1, SHA224, SHA256, SHA384, SHA512, Tiger, Whirlpool, MD5, Blake2, Ripemd160
 * Encoding: base64, hex
 *
 * Asymmetric Encryption:
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
#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
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
#include <crypto++/blake2.h>
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
#include <crypto++/ripemd.h>
#include <crypto++/rsa.h>
#include <crypto++/seal.h>
#include <crypto++/secblock.h>
#include <crypto++/seed.h>
#include <crypto++/serpent.h>
#include <crypto++/sha.h>
#include <crypto++/simon.h>
#include <crypto++/speck.h>
#include <crypto++/tiger.h>
#include <crypto++/twofish.h>
#include <crypto++/whrlpool.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/pssr.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

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
#define __hint_encryption_algo_accept__ __attribute__((cold, nothrow, warn_unused_result, pure, no_sanitize_address, no_stack_protector, optimize(3)))
#define __hint_hash__ __attribute__((stack_protect, zero_call_used_regs("used"), warn_unused_result, access(read_only, 1), optimize(3)))
#define __hint_encrypt__ __attribute__((warn_unused_result, zero_call_used_regs("used"), stack_protect, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __hint_decrypt__ __attribute__((warn_unused_result, zero_call_used_regs("used"), stack_protect, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __hint_base64_encode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_base64_decode__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), optimize("3")))
#define __hint_hex_encode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_hex_decode__ __attribute__((warn_unused_result, no_stack_protector, access(read_only, 1), optimize("3")))
#define __hint_generate_rsa_key_der_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_generate_rsa_key_pem_pair__ __attribute__((cold, warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_sign_message__ __attribute__((warn_unused_result, stack_protect, access(read_only, 1), zero_call_used_regs("used"), optimize("3")))
#define __hint_verify_signature__                                                                                                                                                            \
    __attribute__((warn_unused_result, access(read_only, 1), access(read_only, 2), access(read_only, 3), stack_protect, zero_call_used_regs("used"), optimize("3")))
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
#define __hint_prepare_secure_keys__ __attribute__((stack_protect, zero_call_used_regs("used"), optimize("3")))
#define __hint_cipher_transformation__ __attribute__((warn_unused_result, stack_protect, zero_call_used_regs("used"), noinline, access(read_only, 1), access(read_only, 2), optimize("3")))

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
 *
 */

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
using gost_t = CryptoPP::GOST;
using hash_transformer_t = CryptoPP::HashTransformation;
using hash_filter_t = CryptoPP::HashFilter;

using cbc_aes_encryption_t = CryptoPP::CBC_Mode<cbc_cipher_t>::Encryption;
using cbc_blowfish_encryption_t = CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption;
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

typedef op_frame<string_t> encryption_result;

typedef op_frame<string_t> decryption_result;

typedef struct alignas(void *)
{
    std::uint16_t secure_key{};
    std::uint16_t secure_ivector{};
} mode_of_operation_map;

typedef struct alignas(void *)
{
    std::unordered_map<e_cbc_algorithm, mode_of_operation_map> cbc{};
    std::unordered_map<e_gcm_algorithm, mode_of_operation_map> gcm{};
    std::unordered_map<e_eax_algorithm, mode_of_operation_map> eax{};
} operation_mode;

/**
 * --------------------------------------------------------------------------------------------
 *
 * Available algorithms for each operation mode available, add more algorithms if required.   |
 *
 * --------------------------------------------------------------------------------------------
 */
std::unordered_map<e_cbc_algorithm, mode_of_operation_map> cbc_map_block{
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
};
std::unordered_map<e_gcm_algorithm, mode_of_operation_map> gcm_map_block{
    {e_gcm_algorithm::AES, mode_of_operation_map{.secure_key{e_key_block_size::AES}, .secure_ivector{e_iv_block_size::AES}}},
    {e_gcm_algorithm::MARS, mode_of_operation_map{.secure_key{e_key_block_size::MARS}, .secure_ivector{e_iv_block_size::MARS}}},
    {e_gcm_algorithm::RC6, mode_of_operation_map{.secure_key{e_key_block_size::RC6}, .secure_ivector{e_iv_block_size::RC6}}},
    {e_gcm_algorithm::TWOFISH, mode_of_operation_map{.secure_key{e_key_block_size::TWOFISH}, .secure_ivector{e_iv_block_size::TWOFISH}}}};
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
        .cbc{cbc_map_block}, // CBC mode of operation supported algorithms and key/initialization vector block size
        .gcm{gcm_map_block}, // GCM mode of operation supported algorithms and key/initialization vector block size
        .eax{eax_map_block}, // EAX mode of operation supported algorithms and key/initialization vector block size
    };

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
     * Hash buffer with sha algorithm and return hashed result.
     * @param string_view_t buffer to hash
     * @param e_hash_algo_option hash algorithm
     * @returns op_frame<string_t> structure containing error and result blocks.
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

    __hint_cipher_transformation__ const encryption_result cbc_encrypt(const string_t &buffer, const string_t &secret, const e_cbc_algorithm algorithm = e_cbc_algorithm::AES)
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
            this->__prepare_cbc_secure_keys(secret, secure_key, initialization_vector, salt, sizeof(salt), algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("Error during secure key/iv prepare!");
            if (algorithm == e_cbc_algorithm::AES)
                this->__cbc_execute<cbc_aes_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::ARIA)
                this->__cbc_execute<cbc_aria_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::BLOWFISH)
                this->__cbc_execute<cbc_blowfish_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::CAST128)
                this->__cbc_execute<cbc_cast128_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::CAST256)
                this->__cbc_execute<cbc_cast256_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::GOST)
                this->__cbc_execute<cbc_gost_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::HIGHT)
                this->__cbc_execute<cbc_hight_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::IDEA)
                this->__cbc_execute<cbc_idea_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::MARS)
                this->__cbc_execute<cbc_mars_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::RC2)
                this->__cbc_execute<cbc_rc2_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::RC5)
                this->__cbc_execute<cbc_rc5_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::RC6)
                this->__cbc_execute<cbc_rc6_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::SEED)
                this->__cbc_execute<cbc_seed_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::SERPENT)
                this->__cbc_execute<cbc_serpent_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::SIMON128)
                this->__cbc_execute<cbc_simon128_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else if (algorithm == e_cbc_algorithm::SPECK128)
                this->__cbc_execute<cbc_speck128_encryption_t>(secure_key, initialization_vector, buffer, r0);
            else
                throw std::invalid_argument("invalid cbc algorithm!");

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

    __hint_cipher_transformation__ const decryption_result cbc_decrypt(const string_t &buffer, const string_t &secret, const e_cbc_algorithm algorithm = e_cbc_algorithm::AES)
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
            this->__prepare_cbc_secure_keys(secret, secure_key, initialization_vector, salt, sizeof(salt), algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("error during key/iv preparation!");
            if (algorithm == e_cbc_algorithm::AES)
                this->__cbc_execute<cbc_aes_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::ARIA)
                this->__cbc_execute<cbc_aria_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::BLOWFISH)
                this->__cbc_execute<cbc_blowfish_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::CAST128)
                this->__cbc_execute<cbc_cast128_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::CAST256)
                this->__cbc_execute<cbc_cast256_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::GOST)
                this->__cbc_execute<cbc_gost_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::HIGHT)
                this->__cbc_execute<cbc_hight_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::IDEA)
                this->__cbc_execute<cbc_idea_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::MARS)
                this->__cbc_execute<cbc_mars_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::RC2)
                this->__cbc_execute<cbc_rc2_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::RC5)
                this->__cbc_execute<cbc_rc5_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::RC6)
                this->__cbc_execute<cbc_rc6_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::SEED)
                this->__cbc_execute<cbc_seed_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::SERPENT)
                this->__cbc_execute<cbc_serpent_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::SIMON128)
                this->__cbc_execute<cbc_simon128_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else if (algorithm == e_cbc_algorithm::SPECK128)
                this->__cbc_execute<cbc_speck128_decryption_t>(secure_key, initialization_vector, ciphertext, r0);
            else
                throw std::invalid_argument("invalid cbc algorithm!");

            result.result = std::move(r0);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    };

    __hint_cipher_transformation__ const encryption_result gcm_encrypt(const string_t &plaintext_cipher, const string_t &secret, const e_gcm_algorithm algorithm = e_gcm_algorithm::AES)
    {
        encryption_result result;
        try
        {
            string_t encrypted_block, encoded_block;
            sec_byte_block_t key, iv;
            this->__prepare_gcm_secure_keys(secret, key, iv, algorithm);
            if (algorithm == e_gcm_algorithm::AES)
                this->__gcm_execute<gcm_aes_encryption_t>(key, iv, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_gcm_algorithm::MARS)
                this->__gcm_execute<gcm_mars_encryption_t>(key, iv, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_gcm_algorithm::RC6)
                this->__gcm_execute<gcm_rc6_encryption_t>(key, iv, plaintext_cipher, encrypted_block, encoded_block);
            else if (algorithm == e_gcm_algorithm::TWOFISH)
                this->__gcm_execute<gcm_twofish_encryption_t>(key, iv, plaintext_cipher, encrypted_block, encoded_block);
            else
                throw std::invalid_argument("invalid gcm algorithm!");
            result.result = std::move(encoded_block);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
    }

    __hint_cipher_transformation__ const decryption_result gcm_decrypt(const string_t &encrypted_cipher, const string_t &secret, const e_gcm_algorithm algorithm = e_gcm_algorithm::AES)
    {
        decryption_result result{.error{.has_error{false}}};
        try
        {
            const std::uint16_t iv_block_size(this->op_mode.gcm.at(algorithm).secure_ivector);
            string_t decrypted_block, decoded_block;
            string_source_t(encrypted_cipher, true, new hex_decoder_t(new string_sink_t(decoded_block)));
            sec_byte_block_t secure_key, initialization_vector;
            this->__prepare_gcm_secure_keys(secret, secure_key, initialization_vector, algorithm);
            if (secure_key.empty() || initialization_vector.empty())
                throw std::runtime_error("error during key/iv preparation!");
            if (algorithm == e_gcm_algorithm::AES)
                this->__gcm_reverse_execution<gcm_aes_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_gcm_algorithm::MARS)
                this->__gcm_reverse_execution<gcm_mars_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_gcm_algorithm::RC6)
                this->__gcm_reverse_execution<gcm_rc6_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else if (algorithm == e_gcm_algorithm::TWOFISH)
                this->__gcm_reverse_execution<gcm_twofish_decryption_t>(secure_key, initialization_vector, iv_block_size, decoded_block, decrypted_block);
            else
                throw std::invalid_argument("invalid gcm algorithm!");
            result.result = std::move(decrypted_block);
        }
        catch (const std::exception &e)
        {
            result.error.has_error = true;
            result.error.error_msg = e.what();
        }
        return result;
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
            std::cerr << "hex encoded buffer length error!\n";
            return "";
        }
        string_t hex_decoded;
        hex_decoded.reserve(hex_encoded.length() / 2);
        for (std::size_t _i{0}; _i < hex_encoded.length(); _i += 2)
            hex_decoded.push_back(static_cast<char>(std::stoi(string_t(hex_encoded.substr(_i, 2)), nullptr, 16)));

        return hex_decoded;
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
    __temp_cipher_exec__ inline void __cbc_execute(sec_byte_block_t &key, sec_byte_block_t &iv, const string_t &source, string_t &output)
    {
        cipher_mode executor;
        executor.SetKeyWithIV(key, key.size(), iv);
        string_source_t(source, true, new transformer_filter_t(executor, new string_sink_t(output)));
    };

    __temp_cipher_exec__ inline void __gcm_execute(sec_byte_block_t &key, sec_byte_block_t &iv, const string_t &plaintext_cipher, string_t &encrypted_block, string_t &encoded_block)
    {
        cipher_mode encryption;
        encryption.SetKeyWithIV(key, key.size(), iv, iv.size());
        string_source_t(plaintext_cipher, true, new auth_encryption_filter_t(encryption, new string_sink_t(encrypted_block)));
        encrypted_block = string_t((const char *)iv.data(), iv.size()) + encrypted_block;
        string_source_t(encrypted_block, true, new hex_encoder_t(new string_sink_t(encoded_block)));
    };

    __temp_cipher_exec__ inline void __gcm_reverse_execution(sec_byte_block_t &key, sec_byte_block_t &iv, const std::uint16_t iv_block_size, const string_t &decoded_block,
                                                             string_t &decrypted_block)
    {
        iv = sec_byte_block_t((const byte *)decoded_block.data(), iv_block_size);
        string_t ciphertext = decoded_block.substr(iv_block_size);
        cipher_mode decryption;
        decryption.SetKeyWithIV(key, key.size(), iv, iv.size());
        string_source_t(ciphertext, true, new auth_decryption_filter_t(decryption, new string_sink_t(decrypted_block)));
    };

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

    __hint_prepare_secure_keys__ inline void __prepare_cbc_secure_keys(const string_t &cipher, sec_byte_block_t &key, sec_byte_block_t &iv, const byte *salt, const std::size_t salt_size,
                                                                       const e_cbc_algorithm algorithm)
    {
        sha256_hmac_t hmac;
        const std::uint16_t key_size = this->op_mode.cbc.at(algorithm).secure_key;
        const std::uint16_t iv_size = this->op_mode.cbc.at(algorithm).secure_ivector;

        key.CleanNew(key_size);
        iv.CleanNew(iv_size);
        hmac.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
        hmac.DeriveKey(iv, iv.size(), 0, reinterpret_cast<const byte *>(cipher.data()), cipher.length(), salt, salt_size, this->cipher_iteration_count);
    };

    __hint_prepare_secure_keys__ inline void __prepare_gcm_secure_keys(const string_t &secret, sec_byte_block_t &key, sec_byte_block_t &iv, const e_gcm_algorithm algorithm)
    {
        CryptoPP::SHA256 hash;
        key.resize(this->op_mode.gcm.at(algorithm).secure_key);
        hash.CalculateDigest(key, (const byte *)secret.data(), secret.size());
        iv.resize(this->op_mode.gcm.at(algorithm).secure_ivector);
        entropy_seed_t rng;
        rng.GenerateBlock(iv, iv.size());
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
