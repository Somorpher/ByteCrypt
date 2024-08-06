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

#ifndef __MODULE_BYTE_CRYPT__

#define __MODULE_BYTE_CRYPT__ 1

namespace ByteCryptModule
{

    /*                      Namespace                        *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    enum class eHashAlgo
    {
        SHA1 = 0,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    };

    /*                      Type Alias                       *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    using String_t = std::basic_string<char>;
    using StringView_t = std::basic_string_view<char>;

    class ByteCrypt
    {
    public:
        ByteCrypt() {};

        const String_t Hash(const String_t buffer, const eHashAlgo sha = eHashAlgo::SHA256)
        {
            String_t digest_block;
            if (sha == eHashAlgo::SHA1)
            {
                CryptoPP::SHA1 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == eHashAlgo::SHA224)
            {
                CryptoPP::SHA224 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == eHashAlgo::SHA256)
            {
                CryptoPP::SHA256 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == eHashAlgo::SHA384)
            {
                CryptoPP::SHA384 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == eHashAlgo::SHA512)
            {
                CryptoPP::SHA512 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            else if (sha == eHashAlgo::SHA384)
            {
                CryptoPP::SHA384 algo;
                CryptoPP::StringSource digSource(buffer, true, new CryptoPP::HashFilter(algo, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest_block))));
            }
            return digest_block;
        };
        const String_t Encrypt(const StringView_t plain_text, const StringView_t key)
        {
            return "";
        };
        const String_t Decrypt(const StringView_t cipher, const StringView_t key)
        {
            return "";
        };

        ~ByteCrypt() {};
    };
};

#endif
