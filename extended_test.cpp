/**
 * 
 * *************************************** READ THIS ****************************
 * 
 * this will look bloated but it was intentional to use this level of verbosity, 
 * it is better for showing all possible modes, algorithms, etc... available within the class.
 * this actually could be done in 1/4 of the current size i know :)
 * 
 */


#include "modules/ByteCrypt-module/ByteCrypt.hpp" // NOTE: assuming the ByteCrypt.hpp is in the same directory

using string_t = std::string;

using namespace ByteCryptModule;

int main(int argc, char *argv[])
{

    std::cout << "Extended ByteCrypt Test:\n\n";
    
    ByteCrypt bCrypt; // new instance

    string_t buffer("urmother");

    std::cout << "Plain Text Buffer = " << buffer << "\n";

    // ----------------- HASHING --------------------

    std::cout << "Test Subject: HASH\n\n";

    string_t buffer_hash = bCrypt.hash(buffer,e_hash_algo_option::SHA1);

    std::cout << "Hash with SHA1     : " << buffer_hash << '\n';

    buffer_hash = bCrypt.hash(buffer, e_hash_algo_option::SHA224);

    std::cout << "Hash with SHA224   : " << buffer_hash << "\n";

    buffer_hash = bCrypt.hash(buffer, e_hash_algo_option::SHA256);

    std::cout << "Hash with SHA256   : " << buffer_hash << "\n";

    buffer_hash = bCrypt.hash(buffer, e_hash_algo_option::SHA384);

    std::cout << "Hash with SHA384   : " << buffer_hash << "\n";

    buffer_hash = bCrypt.hash(buffer, e_hash_algo_option::SHA512);

    std::cout << "Hash with SHA512   : " << buffer_hash << "\n";

   // ----------------- ENCODING ------------------

   std::cout << "\nTest Subject: ENCODER/DECODED\n\n";

   string_t b64_encoded = bCrypt.base64_encode(buffer);

   std::cout << "Base64 Encoded      : " << b64_encoded << "\n";
   
   string_t b64_decoded = bCrypt.base64_decode(b64_encoded);

   std::cout << "Base64 Decoded      : " << b64_decoded << '\n';

   string_t hex_encoded = bCrypt.hex_encode(buffer);
   std::cout << "\n";
   
   std::cout << "Hex Encoded         : " << hex_encoded << "\n";

   string_t hex_decoded = bCrypt.hex_decode(hex_encoded);

   std::cout << "Hex Decoded         : " << hex_decoded << '\n';

   // ----------------- RSA KEYS ------------------

   std::cout << "\nTest Subject: RSA DER PK Gen\n\n";

   rsa_key_pair_struct pk_block = bCrypt.generate_rsa_key_der_pair(512);

   std::cout << "Generate pair DER of RSA private/public keys of size(512):\n\n";
   
   std::cout << "DER Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "DER Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "DER Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_der_pair(1024);

   std::cout << "Generate pair DER of RSA private/public keys of size(1024):\n\n";
   
   std::cout << "DER Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "DER Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "DER Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_der_pair(2048);

   std::cout << "Generate pair DER of RSA private/public keys of size(2048):\n\n";
   
   std::cout << "DER Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "DER Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "DER Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_der_pair(3072);

   std::cout << "Generate pair DER of RSA private/public keys of size(3072):\n\n";
   
   std::cout << "DER Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "DER Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "DER Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_der_pair(4096);

   std::cout << "Generate pair DER of RSA private/public keys of size(4096):\n\n";
   
   std::cout << "DER Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "DER Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "DER Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';
 
   std::cout << "\nTest Subject: RSA PEM PK Gen\n\n";

   pk_block = bCrypt.generate_rsa_key_pem_pair(512);

   std::cout << "Generate pair PEM of RSA private/public keys of size(512):\n\n";
   
   std::cout << "PEM Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "PEM Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "PEM Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_pem_pair(1024);

   std::cout << "Generate pair PEM of RSA private/public keys of size(1024):\n\n";
   
   std::cout << "PEM Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "PEM Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "PEM Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_pem_pair(2048);

   std::cout << "Generate pair PEM of RSA private/public keys of size(2048):\n\n";
   
   std::cout << "PEM Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "PEM Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "PEM Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_pem_pair(3072);

   std::cout << "Generate pair PEM of RSA private/public keys of size(3072):\n\n";
   
   std::cout << "PEM Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "PEM Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "PEM Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   pk_block = bCrypt.generate_rsa_key_pem_pair(4096);

   std::cout << "Generate pair PEM of RSA private/public keys of size(4096):\n\n";
   
   std::cout << "PEM Public/Private key Status: " << (pk_block.state ? " Success!" : " Failure!") << "\n\n";

   std::cout << "PEM Generated Public Key: \n";
   std::cout << pk_block.public_key.value_or(" not generated!") << '\n';

   std::cout << "PEM Generated Private Key: \n";
   std::cout << pk_block.private_key.value_or(" not generated!") << '\n';

   // ------------------ RSA Keys Storing/Loading ------------------
   std::cout << "\nTest Subject: RSA Key Store/Load\n\n";

   std::cout << "Generate RSA(512) Public/Private keys for Loading/Storing operations...\n";

   rsa_key_pair_struct key_pair = bCrypt.generate_rsa_key_pem_pair(512); // use small key size for test output readability

   std::cout << "Rsa Public/Private key Generation Result: " << (key_pair.state ? " Success!" : " Failure!") << "\n";

   if(!key_pair.state) return 1;

   std::cout << "Store Public/Private Keys...\n";

   if(!bCrypt.save_rsa_key("pub.pem", key_pair.public_key.value())) return 1;

   std::cout << "Public Key stored!\n";

   if(!bCrypt.save_rsa_key("priv.pem", key_pair.private_key.value()));

   std::cout << "Private Key stored!\n";

   std::cout << "\nNow load public/private keys...\n";
   
   rsa_key_block_load pub_key_load = bCrypt.load_rsa_key("pub.pem");
   rsa_key_block_load priv_key_load = bCrypt.load_rsa_key("priv.pem");

   if(!pub_key_load.status) return 1;

   std::cout << "Public key loaded!\n";

   if(!priv_key_load.status) return 1;

   std::cout << "Private Key loaded!\n\n";

   std::cout << "Loaded Public Key: \n" << pub_key_load.key << "\n";

   std::cout << "Loaded Private Key: \n" << priv_key_load.key << "\n";

   
   // ---------------- SIGNATURE/AUTHENTICATION -----------------
   string_t message = "some message to sign";

   std::cout << "Generate Signature...\n";

   string_t signature = bCrypt.sign_message(message, priv_key_load.key);

   if(signature.empty()) return 1;

   std::cout << "Signature Generated, signature is:\n";

   std::cout << signature << "\n\n";

   std::cout << "Now Verify message signature...\n";

   std::cout << "Signature Verification: ";

   if(!bCrypt.verify_signature(message, signature, pub_key_load.key)) {
    std::cout << "Failured!\n";
    return 1;
   };
   
   std::cout << "Success!\n";


    
    return EXIT_SUCCESS;
}
