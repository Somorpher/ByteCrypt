#pragma once

/**
 * ============================================================================
 * ByteCrypt Class - A C++ Data Encryption Utility Module
 * ============================================================================
 *
 * DISCLAIMER OF WARRANTY:
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the author(s) be held liable for any damages arising from
 * the use of this software, including but not limited to:
 *
 * - Loss of data
 * - Any other type of loss or damage
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would
 *    be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not
 *    be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * LIMITATION OF LIABILITY:
 *
 * In no event will the author(s) be liable for any damages, including but
 * not limited to incidental, consequential, or punitive damages, arising
 * out of the use of this software.
 *
 * COPYING AND DISTRIBUTION:
 *
 * This software may be copied and distributed free of charge, provided
 * that the above copyright notice, disclaimer, and limitations of liability
 * are included in all copies.
 *
 * AUTHORIZATION:
 *
 * By using this software, you acknowledge that you have read and understood
 * the terms and conditions of this license, and agree to be bound by them.
 *
 * TRADEMARKS:
 *
 * The names of actual companies and products mentioned in this software
 * may be the trademarks of their respective owners.
 *
 * ACKNOWLEDGMENT:
 *
 * The authors would like to acknowledge the contributions of the C++
 * community, and the many individuals who have helped shape the C++
 * standard library.
 *
 * ============================================================================
 *
 * Written by [Somorpher], [2024].
 */

// Platform detection
#if defined(__linux__) || defined(__APPLE__)


// architecture detection
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__M_X64)

#include <assert.h>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/base64.h>
#include <crypto++/blowfish.h>
#include <crypto++/cast.h>
#include <crypto++/filters.h>
#include <crypto++/gcm.h>
#include <crypto++/hex.h>
#include <crypto++/idea.h>
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
#include <crypto++/serpent.h>
#include <crypto++/gost.h>
#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <crypto++/twofish.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/pssr.h>

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__ 1

// ft. Somorpher

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

// makes code more readable instead of using inline attributes directly with function defintion

/*                      Attribution                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#if defined(__GNUC__) || defined(__clang__)

#define __hint_encryption_algo_accept__ __attribute__((cold, nothrow, warn_unused_result, pure, no_sanitize_address, no_stack_protector, optimize(3)))
#define __hint_hash__ __attribute__((stack_protect, zero_call_used_regs("all"), warn_unused_result, access(read_only, 1), optimize(3)))
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
#define __hint_perform_encryption__ __attribute__((always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), access(read_only, 1), optimize("3")))
#define __hint_perform_decryption__ __attribute__((always_inline, stack_protect, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), access(read_only, 1), optimize("3")))

#else

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
#define __hint_perform_encryption__ [[]]
#define __hint_perform_decryption__ [[]]

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

enum class e_symmetric_algo
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
    GOST
};

// struct but not regular purpose... goes here...
struct e_key_block_size {
    static const std::size_t
    AES = CryptoPP::AES::DEFAULT_KEYLENGTH,
    BLOWFISH = CryptoPP::Blowfish::DEFAULT_KEYLENGTH,
    CAST128 = CryptoPP::CAST128::DEFAULT_KEYLENGTH,
    CAST256 = CryptoPP::CAST256::DEFAULT_KEYLENGTH,
    IDEA = CryptoPP::IDEA::DEFAULT_KEYLENGTH,
    RC2 = CryptoPP::RC2::DEFAULT_KEYLENGTH,
    RC5 = CryptoPP::RC5::DEFAULT_KEYLENGTH,
    RC6 = CryptoPP::RC6::DEFAULT_KEYLENGTH,
    MARS = CryptoPP::MARS::DEFAULT_KEYLENGTH,
    SERPENT = CryptoPP::Serpent::DEFAULT_KEYLENGTH,
    GOST = CryptoPP::GOST::DEFAULT_KEYLENGTH;
};

struct e_iv_block_size {
    static const std::size_t
    AES = CryptoPP::AES::BLOCKSIZE,
    BLOWFISH = CryptoPP::Blowfish::BLOCKSIZE,
    CAST128 = CryptoPP::CAST128::BLOCKSIZE,
    CAST256 = CryptoPP::CAST256::BLOCKSIZE,
    IDEA = CryptoPP::IDEA::BLOCKSIZE,
    RC2 = CryptoPP::RC2::BLOCKSIZE,
    RC5 = CryptoPP::RC5::BLOCKSIZE,
    RC6 = CryptoPP::RC6::BLOCKSIZE,
    MARS = CryptoPP::MARS::BLOCKSIZE,
    SERPENT = CryptoPP::Serpent::BLOCKSIZE,
    GOST = CryptoPP::AES::BLOCKSIZE;
};

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

/**
 * GCM Mode Encryption/Dec(> CBC)
 */
using gcm_aes_encryption_t = CryptoPP::GCM<cbc_cipher_t>::Encryption;
using gcm_blowfish_encryption_t = CryptoPP::GCM<CryptoPP::Blowfish>::Encryption;
using gcm_twofish_encryption_t = CryptoPP::GCM<CryptoPP::Twofish>::Encryption;
using gcm_cast128_encryption_t = CryptoPP::GCM<CryptoPP::CAST128>::Encryption;
using gcm_cast256_encryption_t = CryptoPP::GCM<CryptoPP::CAST256>::Encryption;
using gcm_idea_encryption_t = CryptoPP::GCM<CryptoPP::IDEA>::Encryption;
using gcm_rc2_encryption_t = CryptoPP::GCM<CryptoPP::RC2>::Encryption;
using gcm_rc5_encryption_t = CryptoPP::GCM<CryptoPP::RC5>::Encryption;
using gcm_rc6_encryption_t = CryptoPP::GCM<CryptoPP::RC6>::Encryption;
using gcm_mars_encryption_t = CryptoPP::GCM<CryptoPP::MARS>::Encryption;

using gcm_aes_decryption_t = CryptoPP::GCM<cbc_cipher_t>::Decryption;
using gcm_blowfish_decryption_t = CryptoPP::GCM<CryptoPP::Blowfish>::Decryption;
using gcm_twofish_decryption_t = CryptoPP::GCM<CryptoPP::Twofish>::Decryption;
using gcm_cast128_decryption_t = CryptoPP::GCM<CryptoPP::CAST128>::Decryption;
using gcm_cast256_decryption_t = CryptoPP::GCM<CryptoPP::CAST256>::Decryption;
using gcm_idea_decryption_t = CryptoPP::GCM<CryptoPP::IDEA>::Decryption;
using gcm_rc2_decryption_t = CryptoPP::GCM<CryptoPP::RC2>::Decryption;
using gcm_rc5_decryption_t = CryptoPP::GCM<CryptoPP::RC5>::Decryption;
using gcm_rc6_decryption_t = CryptoPP::GCM<CryptoPP::RC6>::Decryption;
using gcm_mars_decryption_t = CryptoPP::GCM<CryptoPP::MARS>::Decryption;

/*                      Type Traits                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
template <typename mT> __hint_encryption_algo_accept__ static constexpr bool cbc_encryption_algo_accept()
{
    return std::is_same_v<mT, cbc_aes_encryption_t> || std::is_same_v<mT, cbc_blowfish_encryption_t> || std::is_same_v<mT, cbc_twofish_encryption_t> || std::is_same_v<mT, cbc_cast128_encryption_t> || std::is_same_v<mT, cbc_cast256_encryption_t> || std::is_same_v<mT, cbc_idea_encryption_t> ||
           std::is_same_v<mT, cbc_rc2_encryption_t> || std::is_same_v<mT, cbc_rc5_encryption_t> || std::is_same_v<mT, cbc_rc6_encryption_t> || std::is_same_v<mT, cbc_mars_encryption_t> || std::is_same_v<mT, cbc_aes_decryption_t> || std::is_same_v<mT, cbc_blowfish_decryption_t> ||
           std::is_same_v<mT, cbc_twofish_decryption_t> || std::is_same_v<mT, cbc_cast128_decryption_t> || std::is_same_v<mT, cbc_cast256_decryption_t> || std::is_same_v<mT, cbc_idea_decryption_t> || std::is_same_v<mT, cbc_rc2_decryption_t> || std::is_same_v<mT, cbc_rc5_decryption_t> ||
           std::is_same_v<mT, cbc_rc6_decryption_t> || std::is_same_v<mT, cbc_mars_decryption_t> ||  std::is_same_v<mT, cbc_serpent_encryption_t> || std::is_same_v<mT, cbc_gost_encryption_t> || std::is_same_v<mT, cbc_serpent_decryption_t> || std::is_same_v<mT, cbc_gost_decryption_t>;
};

template <typename mT> struct is_accepted_cbc_encryption_algorithm
{
    static constexpr bool value = cbc_encryption_algo_accept<mT>();
};

template <typename mT> constexpr bool is_accepted_cbc_encryption_algorithm_v = is_accepted_cbc_encryption_algorithm<mT>::value;

template <typename mT> __hint_encryption_algo_accept__ static constexpr bool gcm_encryption_algo_accept()
{
    return std::is_same_v<mT, gcm_aes_encryption_t> || std::is_same_v<mT, gcm_blowfish_encryption_t> || std::is_same_v<mT, gcm_twofish_encryption_t> || std::is_same_v<mT, gcm_cast128_encryption_t> || std::is_same_v<mT, gcm_cast256_encryption_t> || std::is_same_v<mT, gcm_idea_encryption_t> ||
           std::is_same_v<mT, gcm_rc2_encryption_t> || std::is_same_v<mT, gcm_rc5_encryption_t> || std::is_same_v<mT, gcm_rc6_encryption_t> || std::is_same_v<mT, gcm_mars_encryption_t> || std::is_same_v<mT, gcm_aes_decryption_t> || std::is_same_v<mT, gcm_blowfish_decryption_t> ||
           std::is_same_v<mT, gcm_twofish_decryption_t> || std::is_same_v<mT, gcm_cast128_decryption_t> || std::is_same_v<mT, gcm_cast256_decryption_t> || std::is_same_v<mT, gcm_idea_decryption_t> || std::is_same_v<mT, gcm_rc2_decryption_t> || std::is_same_v<mT, gcm_rc5_decryption_t> ||
           std::is_same_v<mT, gcm_rc6_decryption_t> || std::is_same_v<mT, gcm_mars_decryption_t>;
};

template <typename mT> struct is_accepted_gcm_encryption_algorithm
{
    static constexpr bool value = gcm_encryption_algo_accept<mT>();
};

template <typename mT> constexpr bool is_accepted_gcm_encryption_algorithm_v = is_accepted_gcm_encryption_algorithm<mT>::value;

#define __temp_perform_keyiv_cbc_intersection__ template <typename cipherT, typename = std::enable_if_t<std::is_class_v<cipherT> && is_accepted_cbc_encryption_algorithm_v<cipherT>>>
#define __temp_perform_keyiv_gcm_intersection__ template <typename cipherT, typename = std::enable_if_t<std::is_class_v<cipherT> && is_accepted_gcm_encryption_algorithm_v<cipherT>>>

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
__temp_byte_crypt__ class ByteCrypt
{
    const std::uint16_t cipher_iteration_count = 10000;
    const std::uint8_t default_sec_key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
    const std::uint8_t default_sec_iv_size = CryptoPP::AES::BLOCKSIZE;
    const std::array<std::uint16_t, 5> rsa_key_size_options{512u, 1024u, 2048u, 3072u, 4096u};

    byte __key__[key_size_t];
    byte __iv__[iv_size_t];

  public:
    ByteCrypt() = default;
    ByteCrypt(const ByteCrypt &) = delete;
    ByteCrypt &operator=(const ByteCrypt &) = delete;
    ByteCrypt(ByteCrypt &&) = delete;
    ByteCrypt &operator=(ByteCrypt &&) = delete;

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
     * encrypt plain_text using key for encryption and alog as encryption algorithm.
     * @param string_t& buffer to encrypt
     * @param string_t& key to use for encryption
     * @param e_symmetric_algo the algorithm for encryption
     * @returns string_t encrypted cipher
     */
    __hint_encrypt__ const string_t cbc_encrypt(const string_t &plain_text, const string_t &key, const e_symmetric_algo algo)
    {
        string_t cipher, encoded_cipher;
        try
        {
            this->__derive_cbc_key_iv(key, this->__key__, this->__iv__);

            switch (algo)
            {
#define _case(algorithm, encryption_type)                                                                                                                                                                                                                                                                                      \
    case e_symmetric_algo::algorithm:                                                                                                                                                                                                                                                                                          \
        this->__perform_cbc_encryption<encryption_type>(plain_text, cipher, encoded_cipher);                                                                                                                                                                                                                                   \
        break
                _case(AES, cbc_aes_encryption_t);
                _case(BLOWFISH, cbc_blowfish_encryption_t);
                _case(TWOFISH, cbc_twofish_encryption_t);
                _case(CAST128, cbc_cast128_encryption_t);
                _case(CAST256, cbc_cast256_encryption_t);
                _case(IDEA, cbc_idea_encryption_t);
                _case(RC2, cbc_rc2_encryption_t);
                _case(RC5, cbc_rc5_encryption_t);
                _case(RC6, cbc_rc6_encryption_t);
                _case(MARS, cbc_mars_encryption_t);
                _case(SERPENT, cbc_serpent_encryption_t);
                _case(GOST, cbc_gost_encryption_t);
#undef _case
            default:
                std::cerr << "Unsupported encryption algorithm" << std::endl;
                return "";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Encrypt Error: " << e.what() << "\n";
        }
        return encoded_cipher;
    };

    /**
     * decrypt cipher_block with u_key secret key and algo as algorithm.
     * @param string_t& cipher to decrypt
     * @param e_symmetric_algo algorithm used when encrypted.
     * @returns string_t decrypted cipher
     */
    __hint_decrypt__ const string_t cbc_decrypt(const string_t &cipher_block, const e_symmetric_algo algo)
    {
        string_t decrypted_cipher, decoded_cipher;
        try
        {
            switch (algo)
            {
#define _case(algorithm, decryption_type)                                                                                                                                                                                                                                                                                      \
    case e_symmetric_algo::algorithm:                                                                                                                                                                                                                                                                                          \
        this->__perform_cbc_decryption<decryption_type>(cipher_block, decrypted_cipher, decoded_cipher);                                                                                                                                                                                                                       \
        break
                _case(AES, cbc_aes_decryption_t);
                _case(BLOWFISH, cbc_blowfish_decryption_t);
                _case(TWOFISH, cbc_twofish_decryption_t);
                _case(CAST128, cbc_cast128_decryption_t);
                _case(CAST256, cbc_cast256_decryption_t);
                _case(IDEA, cbc_idea_decryption_t);
                _case(RC2, cbc_rc2_decryption_t);
                _case(RC5, cbc_rc5_decryption_t);
                _case(RC6, cbc_rc6_decryption_t);
                _case(MARS, cbc_mars_decryption_t);
                _case(SERPENT, cbc_serpent_decryption_t);
                _case(GOST, cbc_gost_decryption_t);
#undef _case
            default:
                std::cerr << "Invalid decryption algorithm!\n";
                return "";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decryption Error: " << e.what() << "\n";
        }
        return decrypted_cipher;
    };

    /*++++++++++++++++++++++++++++++++++ INIT GCM +++++++++++++++++++++++++++++++++ */

    /**
     * encrypt(GCM) plain_text using key for encryption and alog as encryption algorithm, use this mode when efficiency
     * and security are a must.
     * @param string_t& buffer to encrypt
     * @param string_t& key to use for encryption
     * @param e_symmetric_algo the algorithm for encryption
     * @returns string_t encrypted cipher
     */
    const string_t gcm_encrypt(const string_t &plain_text, const string_t &key, const e_symmetric_algo algo)
    {
        string_t cipher, encoded_cipher;
        try
        {
            this->__derive_gcm_key_iv(key, this->__key__, this->__iv__);

            switch (algo)
            {
#define _case(algorithm, encryption_type)                                                                                                                                                                                                                                                                                      \
    case e_symmetric_algo::algorithm:                                                                                                                                                                                                                                                                                          \
        this->__perform_gcm_encryption<encryption_type>(plain_text, cipher, encoded_cipher);                                                                                                                                                                                                                                   \
        break
                _case(AES, gcm_aes_encryption_t);
                _case(BLOWFISH, gcm_blowfish_encryption_t);
                _case(TWOFISH, gcm_twofish_encryption_t);
                _case(CAST128, gcm_cast128_encryption_t);
                _case(CAST256, gcm_cast256_encryption_t);
                _case(IDEA, gcm_idea_encryption_t);
                _case(RC2, gcm_rc2_encryption_t);
                _case(RC5, gcm_rc5_encryption_t);
                _case(RC6, gcm_rc6_encryption_t);
                _case(MARS, gcm_mars_encryption_t);
#undef _case
            default:
                std::cerr << "Unsupported encryption(GCM) algorithm" << std::endl;
                return "";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "GCMEncrypt Error: " << e.what() << "\n";
        }
        return encoded_cipher;
    };

    /**
     * decrypt(GCM) cipher_block with u_key secret key and algo as algorithm.
     * @param string_t& cipher to decrypt
     * @param e_symmetric_algo algorithm used when encrypted.
     * @returns string_t decrypted cipher
     */
    const string_t gcm_decrypt(const string_t &cipher_block, const e_symmetric_algo algo)
    {
        string_t decrypted_cipher, decoded_cipher;
        try
        {
            switch (algo)
            {
#define _case(algorithm, decryption_type)                                                                                                                                                                                                                                                                                      \
    case e_symmetric_algo::algorithm:                                                                                                                                                                                                                                                                                          \
        this->__perform_gcm_decryption<decryption_type>(const_cast<string_t &>(cipher_block), decrypted_cipher, decoded_cipher);                                                                                                                                                                                               \
        break
                _case(AES, gcm_aes_decryption_t);
                _case(BLOWFISH, gcm_blowfish_decryption_t);
                _case(TWOFISH, gcm_twofish_decryption_t);
                _case(CAST128, gcm_cast128_decryption_t);
                _case(CAST256, gcm_cast256_decryption_t);
                _case(IDEA, gcm_idea_decryption_t);
                _case(RC2, gcm_rc2_decryption_t);
                _case(RC5, gcm_rc5_decryption_t);
                _case(RC6, gcm_rc6_decryption_t);
                _case(MARS, gcm_mars_decryption_t);
#undef _case
            default:
                std::cerr << "Invalid(GCM) decryption algorithm!\n";
                return "";
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "GCMDecryption Error: " << e.what() << "\n";
        }
        return decrypted_cipher;
    };

    /* ++++++++++++++++++++++++++++++++++ END GCM +++++++++++++++++++++++++++++++++++++ */

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

    ~ByteCrypt(){
        std::memset(this->__key__, 0, 0);
        std::memset(this->__iv__, 0, 0);
        std::memset(this->__iv__, 0, 0);
        std::memset(this->__key__, 0, 0);
    };

  private:
    __hint_derive_key_iv__ void __derive_cbc_key_iv(const string_t &u_pwd, byte *key, byte *init_vector) const
    {
        entropy_seed_t entropy;
        byte salt[16];
        entropy.GenerateBlock(salt, sizeof(salt));
        sha256_hmac_t transformer;
        transformer.DeriveKey(key, default_sec_key_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
        transformer.DeriveKey(init_vector, default_sec_iv_size, 0, reinterpret_cast<const byte *>(u_pwd.data()), u_pwd.size(), salt, sizeof(salt), cipher_iteration_count);
    };

    __hint_derive_key_iv__ void __derive_gcm_key_iv(const string_t &u_pwd, byte *key, byte *init_vector) const
    {
        byte random_salt[16];
        entropy_seed_t entropy;
        entropy.GenerateBlock(random_salt, sizeof(random_salt));
        entropy.GenerateBlock(init_vector, sizeof(init_vector));
        hmac_s256_t hmac_converter((const byte *)u_pwd.data(), u_pwd.size());
        hmac_converter.Update(random_salt, sizeof(random_salt));
        hmac_converter.Final(key);
    };

    __temp_perform_keyiv_cbc_intersection__ __hint_perform_keyiv_intersection__ inline void __perform_keyiv_cbc_intersection(cipherT &encryption_class) const noexcept
    {
        encryption_class.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
    };

    __temp_perform_keyiv_gcm_intersection__ __hint_perform_keyiv_intersection__ inline void __perform_keyiv_gcm_intersection(cipherT &encryption_class) const noexcept
    {
        encryption_class.SetKeyWithIV(this->__key__, sizeof(this->__key__), this->__iv__);
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

    __temp_perform_encryption__ __hint_perform_encryption__ inline void __perform_cbc_encryption(const string_t &plain_text, string_t &cipher, string_t &encoded_cipher)
    {
        static_assert(is_accepted_cbc_encryption_algorithm_v<encryptionType>, "not a valid CBC Mode encryption function.");
        encryptionType encryption;
        __perform_keyiv_cbc_intersection<encryptionType>(encryption);
        string_source_t(plain_text, true, new transformer_filter_t(encryption, new string_sink_t(cipher)));
        string_source_t(cipher, true, new hex_encoder_t(new string_sink_t(encoded_cipher)));
    };

    __temp_perform_decryption__ __hint_perform_decryption__ void __perform_cbc_decryption(const string_t &cipher_text, string_t &decrypted_data, string_t &decoded_data)
    {
        static_assert(is_accepted_cbc_encryption_algorithm_v<decryptionType>, "not a valid CBC Mode decryption function.");
        decryptionType decryption;
        __perform_keyiv_cbc_intersection<decryptionType>(decryption);
        string_source_t(cipher_text, true, new hex_decoder_t(new string_sink_t(decoded_data)));
        string_source_t(decoded_data, true, new transformer_filter_t(decryption, new string_sink_t(decrypted_data)));
    };

    __temp_perform_encryption__ __hint_perform_encryption__ inline void __perform_gcm_encryption(const string_t &plain_text, string_t &cipher, string_t &encoded_cipher)
    {
        static_assert(is_accepted_gcm_encryption_algorithm_v<encryptionType>, "not a valid GCM Mode encryption function.");
        encryptionType encryption;
        __perform_keyiv_gcm_intersection<encryptionType>(encryption);
        string_source_t(plain_text, true, new CryptoPP::AuthenticatedEncryptionFilter(encryption, new string_sink_t(cipher)));
        string_source_t(cipher, true, new hex_encoder_t(new string_sink_t(encoded_cipher)));
    };

    __temp_perform_decryption__ __hint_perform_decryption__ void __perform_gcm_decryption(string_t &cipher_text, string_t &decrypted_data, string_t &decoded_data)
    {
        static_assert(is_accepted_gcm_encryption_algorithm_v<decryptionType>, "not a valid GCM Mode decryption function.");
        decryptionType decryption;
        __perform_keyiv_gcm_intersection<decryptionType>(decryption);
        string_source_t(cipher_text, true, new hex_decoder_t(new string_sink_t(decoded_data)));
        CryptoPP::AuthenticatedDecryptionFilter df(decryption, new string_sink_t(decrypted_data));

        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, (const byte *)decoded_data.data(), decoded_data.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        if (!df.GetLastResult()) [[unlikely]]
            throw std::runtime_error("Decryption failed");
    };
};
}; // namespace ByteCryptModule
#endif

#endif

#endif
