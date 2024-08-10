#include "modules/ByteCrypt-module/ByteCrypt.hpp" // NOTE: assuming the ByteCrypt.hpp is in the same directory

using string_t = std::string;
using namespace ByteCryptModule;

int main(int argc, char *argv[])
{

	std::size_t test_score(0), threshold(static_cast<int>(e_cbc_symmetric_algo::__COUNT)+static_cast<int>(e_gcm_symmetric_algo::__COUNT)+static_cast<int>(e_eax_symmetric_algo::__COUNT));
	std::cout << "\n\nInitializing Crypto Test for Operation Modes: CBC, GCM, EAX.\nThreshold = " << threshold << "\n";
  string_t buffer = "plain text", secret = "secretkey";
	
    {
        std::size_t test_counter(0);
        std::cout << "CBC Operation Mode Encryption Test:\n";
        {
            ByteCrypt<32, 16> b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::GOST);
            std::cout << "Encrypted GOST:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::GOST);
            std::cout << "Decrypted GOST:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::AES);
            std::cout << "Encrypted AES:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::AES);
            std::cout << "Decrypted AES:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::ARIA);
            std::cout << "Encrypted ARIA:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::ARIA);
            std::cout << "Decrypted ARIA:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::BLOWFISH);
            std::cout << "Encrypted BLOWFISH:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::BLOWFISH);
            std::cout << "Decrypted BLOWFISH:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::CAST128);
            std::cout << "Encrypted CAST128:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::CAST128);
            std::cout << "Decrypted CAST128:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::CAST256);
            std::cout << "Encrypted CAST256:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::CAST256);
            std::cout << "Decrypted CAST256:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::HIGHT);
            std::cout << "Encrypted HIGHT:     (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::HIGHT);
            std::cout << "Decrypted HIGHT:      " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::IDEA);
            std::cout << "Encrypted IDEA:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::IDEA);
            std::cout << "Decrypted IDEA:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::MARS);
            std::cout << "Encrypted MARS:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::MARS);
            std::cout << "Decrypted MARS:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::RC2);
            std::cout << "Encrypted RC2:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::RC2);
            std::cout << "Decrypted RC2:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::RC5);
            std::cout << "Encrypted RC5:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::RC5);
            std::cout << "Decrypted RC5:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::RC6);
            std::cout << "Encrypted RC6:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::RC6);
            std::cout << "Decrypted RC6:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::SEED);
            std::cout << "Encrypted SEED:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::SEED);
            std::cout << "Decrypted SEED:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::SERPENT);
            std::cout << "Encrypted SERPENT:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::SERPENT);
            std::cout << "Decrypted SERPENT:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::SIMON128);
            std::cout << "Encrypted SIMON128:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::SIMON128);
            std::cout << "Decrypted SIMON128:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::SPECK128);
            std::cout << "Encrypted SPECK128:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::SPECK128);
            std::cout << "Decrypted SPECK128:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.cbc_encrypt(buffer, secret, e_cbc_symmetric_algo::TWOFISH);
            std::cout << "Encrypted TWOFISH:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.cbc_decrypt(encrypted, e_cbc_symmetric_algo::TWOFISH);
            std::cout << "Decrypted TWOFISH:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
		test_score+=test_counter;
        std::cout << "CBC Mode of Operation Encryption Algorithms Test Score: " << test_counter << "/" << static_cast<int>(e_cbc_symmetric_algo::__COUNT) << "\n";
    }


    {
        std::size_t test_counter(0);
        std::cout << "\n\nGCM Operation Mode Encryption Test:\n";
        {
            ByteCrypt b;
            string_t encrypted = b.gcm_encrypt(buffer, secret, e_gcm_symmetric_algo::AES);
            std::cout << "Encrypted AES:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.gcm_decrypt(encrypted, e_gcm_symmetric_algo::AES);
            std::cout << "Decrypted AES:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }

        {
            ByteCrypt b;
            string_t encrypted = b.gcm_encrypt(buffer, secret, e_gcm_symmetric_algo::MARS);
            std::cout << "Encrypted MARS:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.gcm_decrypt(encrypted, e_gcm_symmetric_algo::MARS);
            std::cout << "Decrypted MARS:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.gcm_encrypt(buffer, secret, e_gcm_symmetric_algo::RC6);
            std::cout << "Encrypted RC6:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.gcm_decrypt(encrypted, e_gcm_symmetric_algo::RC6);
            std::cout << "Decrypted RC6:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.gcm_encrypt(buffer, secret, e_gcm_symmetric_algo::TWOFISH);
            std::cout << "Encrypted TWOFISH:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.gcm_decrypt(encrypted, e_gcm_symmetric_algo::TWOFISH);
            std::cout << "Decrypted TWOFISH:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
		test_score+=test_counter;
        std::cout << "GCM Mode of Operation Encryption Algorithms Test Score: " << test_counter << "/" << static_cast<int>(e_gcm_symmetric_algo::__COUNT) << "\n";
    }

    {
        std::size_t test_counter(0);
        std::cout << "\n\nEAX Operation Mode Encryption Test:\n";
        {
            ByteCrypt<32, 16> b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::GOST);
            std::cout << "Encrypted GOST:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::GOST);
            std::cout << "Decrypted GOST:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::SEED);
            std::cout << "Encrypted SEED:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::SEED);
            std::cout << "Decrypted SEED:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::AES);
            std::cout << "Encrypted AES:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::AES);
            std::cout << "Decrypted AES:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::BLOWFISH);
            std::cout << "Encrypted BLOWFISH:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::BLOWFISH);
            std::cout << "Decrypted BLOWFISH:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::CAST128);
            std::cout << "Encrypted CAST128:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::CAST128);
            std::cout << "Decrypted CAST128:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::CAST256);
            std::cout << "Encrypted CAST256:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::CAST256);
            std::cout << "Decrypted CAST256:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::HIGHT);
            std::cout << "Encrypted HIGHT:     (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::HIGHT);
            std::cout << "Decrypted HIGHT:      " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::IDEA);
            std::cout << "Encrypted IDEA:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::IDEA);
            std::cout << "Decrypted IDEA:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::MARS);
            std::cout << "Encrypted MARS:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::MARS);
            std::cout << "Decrypted MARS:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::RC5);
            std::cout << "Encrypted RC5:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::RC5);
            std::cout << "Decrypted RC5:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::RC6);
            std::cout << "Encrypted RC6:       (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::RC6);
            std::cout << "Decrypted RC6:        " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::SEED);
            std::cout << "Encrypted SEED:      (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::SEED);
            std::cout << "Decrypted SEED:       " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::SERPENT);
            std::cout << "Encrypted SERPENT:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::SERPENT);
            std::cout << "Decrypted SERPENT:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::SIMON128);
            std::cout << "Encrypted SIMON128:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::SIMON128);
            std::cout << "Decrypted SIMON128:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::SPECK128);
            std::cout << "Encrypted SPECK128:  (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::SPECK128);
            std::cout << "Decrypted SPECK128:   " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
        {
            ByteCrypt b;
            string_t encrypted = b.eax_encrypt(buffer, secret, e_eax_symmetric_algo::TWOFISH);
            std::cout << "Encrypted TWOFISH:   (" << encrypted.length() << ") " << encrypted << '\n';
            string_t decrypted = b.eax_decrypt(encrypted, e_eax_symmetric_algo::TWOFISH);
            std::cout << "Decrypted TWOFISH:    " << decrypted << "\n";
            if (decrypted.compare(buffer) == 0)
                ++test_counter;
        }
		test_score+=test_counter;
        std::cout << "EAX Mode of Operation Encryption Algorithms Test Score: " << test_counter << "/" << static_cast<int>(e_eax_symmetric_algo::__COUNT) << "\n";
    }
	std::cout <<"\n------------------------------------------------------\n";
	std::cout << "\n[$] Test Finished, test Result = " << (test_score == threshold ? "SUCCESS":"FAILURE")<< "\n";
  ByteCrypt bc;

    return EXIT_SUCCESS;
}
