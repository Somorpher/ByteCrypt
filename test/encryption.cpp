#include "modules/ByteCrypt-module/ByteCrypt.hpp" // NOTE: assuming the ByteCrypt.hpp is in the same directory

using string_t = std::string;
using namespace ByteCryptModule;
 
int main(int argc, char *argv[]) 
{

    std::string buffer("some buffer");
    std::string secret("secret-encryption-key");
    ByteCrypt bCrypt;
    string_t src = "plaintext";

    // Encryption examples for CBC mode
const auto enc1 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::AES);
std::cout << "AES/CBC Encrypted:        " << enc1.result << "\n";
const auto enc2 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::ARIA);
std::cout << "ARIA/CBC Encrypted:       " << enc2.result << "\n";
const auto enc3 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::BLOWFISH);
std::cout << "BLOWFISH/CBC Encrypted:   " << enc3.result << "\n";
const auto enc4 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::CAST128);
std::cout << "CAST128/CBC Encrypted:    " << enc4.result << "\n";
const auto enc5 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::CAST256);
std::cout << "CAST256/CBC Encrypted:    " << enc5.result << "\n";
const auto enc6 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::GOST);
std::cout << "GOST/CBC Encrypted:       " << enc6.result << "\n";
const auto enc7 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::HIGHT);
std::cout << "HIGHT/CBC Encrypted:      " << enc7.result << "\n";
const auto enc8 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::IDEA);
std::cout << "IDEA/CBC Encrypted:       " << enc8.result << "\n";
const auto enc9 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::MARS);
std::cout << "MARS/CBC Encrypted:       " << enc9.result << "\n";
const auto enc10 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::RC2);
std::cout << "RC2/CBC Encrypted:        " << enc10.result << "\n";
const auto enc11 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::RC5);
std::cout << "RC5/CBC Encrypted:        " << enc11.result << "\n";
const auto enc12 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::RC6);
std::cout << "RC6/CBC Encrypted:        " << enc12.result << "\n";
const auto enc13 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::SEED);
std::cout << "SEED/CBC Encrypted:       " << enc13.result << "\n";
const auto enc14 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::SERPENT);
std::cout << "SERPENT/CBC Encrypted:    " << enc14.result << "\n";
const auto enc15 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::SIMON128);
std::cout << "SIMON128/CBC Encrypted:   " << enc15.result << "\n";
const auto enc16 = bCrypt.cbc_encrypt(src, secret, e_cbc_algorithm::SPECK128);
std::cout << "SPECK128/CBC Encrypted:   " << enc16.result << "\n";

// Decryption examples for CBC mode
const auto dec1 = bCrypt.cbc_decrypt(enc1.result, secret, e_cbc_algorithm::AES);
std::cout << "CBC/AES Decrypted:        " << dec1.result << "\n";
const auto dec2 = bCrypt.cbc_decrypt(enc2.result, secret, e_cbc_algorithm::ARIA);
std::cout << "CBC/ARIA Decrypted:       " << dec2.result << "\n";
const auto dec3 = bCrypt.cbc_decrypt(enc3.result, secret, e_cbc_algorithm::BLOWFISH);
std::cout << "CBC/BLOWFISH Decrypted:   " << dec3.result << "\n";
const auto dec4 = bCrypt.cbc_decrypt(enc4.result, secret, e_cbc_algorithm::CAST128);
std::cout << "CBC/CAST128 Decrypted:    " << dec4.result << "\n";
const auto dec5 = bCrypt.cbc_decrypt(enc5.result, secret, e_cbc_algorithm::CAST256);
std::cout << "CBC/CAST256 Decrypted:    " << dec5.result << "\n";
const auto dec6 = bCrypt.cbc_decrypt(enc6.result, secret, e_cbc_algorithm::GOST);
std::cout << "CBC/GOST Decrypted:       " << dec6.result << "\n";
const auto dec7 = bCrypt.cbc_decrypt(enc7.result, secret, e_cbc_algorithm::HIGHT);
std::cout << "CBC/HIGHT Decrypted:      " << dec7.result << "\n";
const auto dec8 = bCrypt.cbc_decrypt(enc8.result, secret, e_cbc_algorithm::IDEA);
std::cout << "CBC/IDEA Decrypted:       " << dec8.result << "\n";
const auto dec9 = bCrypt.cbc_decrypt(enc9.result, secret, e_cbc_algorithm::MARS);
std::cout << "CBC/MARS Decrypted:       " << dec9.result << "\n";
const auto dec10 = bCrypt.cbc_decrypt(enc10.result, secret, e_cbc_algorithm::RC2);
std::cout << "CBC/RC2 Decrypted:        " << dec10.result << "\n";
const auto dec11 = bCrypt.cbc_decrypt(enc11.result, secret, e_cbc_algorithm::RC5);
std::cout << "CBC/RC5 Decrypted:        " << dec11.result << "\n";
const auto dec12 = bCrypt.cbc_decrypt(enc12.result, secret, e_cbc_algorithm::RC6);
std::cout << "CBC/RC6 Decrypted:        " << dec12.result << "\n";
const auto dec13 = bCrypt.cbc_decrypt(enc13.result, secret, e_cbc_algorithm::SEED);
std::cout << "CBC/SEED Decrypted:       " << dec13.result << "\n";
const auto dec14 = bCrypt.cbc_decrypt(enc14.result, secret, e_cbc_algorithm::SERPENT);
std::cout << "CBC/SERPENT Decrypted:    " << dec14.result << "\n";
const auto dec15 = bCrypt.cbc_decrypt(enc15.result, secret, e_cbc_algorithm::SIMON128);
std::cout << "CBC/SIMON128 Decrypted:   " << dec15.result << "\n";
const auto dec16 = bCrypt.cbc_decrypt(enc16.result, secret, e_cbc_algorithm::SPECK128);
std::cout << "CBC/SPECK128 Decrypted:   " << dec16.result << "\n";

// Encryption examples for GCM mode
const auto enc18 = bCrypt.gcm_encrypt(src, secret, e_gcm_algorithm::AES);
std::cout << "AES/GCM Encrypted:        " << enc18.result << "\n";
const auto enc19 = bCrypt.gcm_encrypt(src, secret, e_gcm_algorithm::MARS);
std::cout << "MARS/GCM Encrypted:       " << enc19.result << "\n";
const auto enc20 = bCrypt.gcm_encrypt(src, secret, e_gcm_algorithm::RC6);
std::cout << "RC6/GCM Encrypted:        " << enc20.result << "\n";
const auto enc21 = bCrypt.gcm_encrypt(src, secret, e_gcm_algorithm::TWOFISH);
std::cout << "TWOFISH/GCM Encrypted:    " << enc21.result << "\n";

// Decryption examples for GCM mode
const auto dec18 = bCrypt.gcm_decrypt(enc18.result, secret, e_gcm_algorithm::AES);
std::cout << "GCM/AES Decrypted:        " << dec18.result << "\n";
const auto dec19 = bCrypt.gcm_decrypt(enc19.result, secret, e_gcm_algorithm::MARS);
std::cout << "GCM/MARS Decrypted:       " << dec19.result << "\n";
const auto dec20 = bCrypt.gcm_decrypt(enc20.result, secret, e_gcm_algorithm::RC6);
std::cout << "GCM/RC6 Decrypted:        " << dec20.result << "\n";
const auto dec21 = bCrypt.gcm_decrypt(enc21.result, secret, e_gcm_algorithm::TWOFISH);
std::cout << "GCM/TWOFISH Decrypted:    " << dec21.result << "\n";

// Encryption examples for EAX mode
const auto enc22 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::AES);
std::cout << "AES/EAX Encrypted:        " << enc22.result << "\n";
const auto enc23 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::BLOWFISH);
std::cout << "BLOWFISH/EAX Encrypted:   " << enc23.result << "\n";
const auto enc24 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::CAST128);
std::cout << "CAST128/EAX Encrypted:    " << enc24.result << "\n";
const auto enc25 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::CAST256);
std::cout << "CAST256/EAX Encrypted:    " << enc25.result << "\n";
const auto enc26 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::GOST);
std::cout << "GOST/EAX Encrypted:       " << enc26.result << "\n";
const auto enc27 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::HIGHT);
std::cout << "HIGHT/EAX Encrypted:      " << enc27.result << "\n";
const auto enc28 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::IDEA);
std::cout << "IDEA/EAX Encrypted:       " << enc28.result << "\n";
const auto enc29 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::LEA);
std::cout << "LEA/EAX Encrypted:        " << enc29.result << "\n";
const auto enc30 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::MARS);
std::cout << "MARS/EAX Encrypted:       " << enc30.result << "\n";
const auto enc31 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::RC5);
std::cout << "RC5/EAX Encrypted:        " << enc31.result << "\n";
const auto enc32 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::RC6);
std::cout << "RC6/EAX Encrypted:        " << enc32.result << "\n";
const auto enc33 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::SEED);
std::cout << "SEED/EAX Encrypted:       " << enc33.result << "\n";
const auto enc34 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::SERPENT);
std::cout << "SERPENT/EAX Encrypted:    " << enc34.result << "\n";
const auto enc35 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::SIMON128);
std::cout << "SIMON128/EAX Encrypted:   " << enc35.result << "\n";
const auto enc36 = bCrypt.eax_encrypt(src, secret, e_eax_algorithm::SPECK128);
std::cout << "SPECK128/EAX Encrypted:   " << enc36.result << "\n";

// Decryption examples for EAX mode
const auto dec22 = bCrypt.eax_decrypt(enc22.result, secret, e_eax_algorithm::AES);
std::cout << "EAX/AES Decrypted:        " << dec22.result << "\n";
const auto dec23 = bCrypt.eax_decrypt(enc23.result, secret, e_eax_algorithm::BLOWFISH);
std::cout << "EAX/BLOWFISH Decrypted:   " << dec23.result << "\n";
const auto dec24 = bCrypt.eax_decrypt(enc24.result, secret, e_eax_algorithm::CAST128);
std::cout << "EAX/CAST128 Decrypted:    " << dec24.result << "\n";
const auto dec25 = bCrypt.eax_decrypt(enc25.result, secret, e_eax_algorithm::CAST256);
std::cout << "EAX/CAST256 Decrypted:    " << dec25.result << "\n";
const auto dec26 = bCrypt.eax_decrypt(enc26.result, secret, e_eax_algorithm::GOST);
std::cout << "EAX/GOST Decrypted:       " << dec26.result << "\n";
const auto dec27 = bCrypt.eax_decrypt(enc27.result, secret, e_eax_algorithm::HIGHT);
std::cout << "EAX/HIGHT Decrypted:      " << dec27.result << "\n";
const auto dec28 = bCrypt.eax_decrypt(enc28.result, secret, e_eax_algorithm::IDEA);
std::cout << "EAX/IDEA Decrypted:       " << dec28.result << "\n";
const auto dec29 = bCrypt.eax_decrypt(enc29.result, secret, e_eax_algorithm::LEA);
std::cout << "EAX/LEA Decrypted:        " << dec29.result << "\n";
const auto dec30 = bCrypt.eax_decrypt(enc30.result, secret, e_eax_algorithm::MARS);
std::cout << "EAX/MARS Decrypted:       " << dec30.result << "\n";
const auto dec31 = bCrypt.eax_decrypt(enc31.result, secret, e_eax_algorithm::RC5);
std::cout << "EAX/RC5 Decrypted:        " << dec31.result << "\n";
const auto dec32 = bCrypt.eax_decrypt(enc32.result, secret, e_eax_algorithm::RC6);
std::cout << "EAX/RC6 Decrypted:        " << dec32.result << "\n";
const auto dec33 = bCrypt.eax_decrypt(enc33.result, secret, e_eax_algorithm::SEED);
std::cout << "EAX/SEED Decrypted:       " << dec33.result << "\n";
const auto dec34 = bCrypt.eax_decrypt(enc34.result, secret, e_eax_algorithm::SERPENT);
std::cout << "EAX/SERPENT Decrypted:    " << dec34.result << "\n";
const auto dec35 = bCrypt.eax_decrypt(enc35.result, secret, e_eax_algorithm::SIMON128);
std::cout << "EAX/SIMON128 Decrypted:   " << dec35.result << "\n";
const auto dec36 = bCrypt.eax_decrypt(enc36.result, secret, e_eax_algorithm::SPECK128);
std::cout << "EAX/SPECK128 Decrypted:   " << dec36.result << "\n";

// Encryption examples for CFB mode
const auto encCFB1 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::AES);
std::cout << "AES/CFB Encrypted:        " << encCFB1.result << "\n";
const auto encCFB2 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::BLOWFISH);
std::cout << "BLOWFISH/CFB Encrypted:   " << encCFB2.result << "\n";
const auto encCFB3 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::CAST128);
std::cout << "CAST128/CFB Encrypted:    " << encCFB3.result << "\n";
const auto encCFB4 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::CAST256);
std::cout << "CAST256/CFB Encrypted:    " << encCFB4.result << "\n";
const auto encCFB5 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::IDEA);
std::cout << "IDEA/CFB Encrypted:       " << encCFB5.result << "\n";
const auto encCFB6 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::RC2);
std::cout << "RC2/CFB Encrypted:        " << encCFB6.result << "\n";
const auto encCFB7 = bCrypt.cfb_encrypt(src, secret, e_cfb_algorithm::RC5);
std::cout << "RC5/CFB Encrypted:        " << encCFB7.result << "\n";

// Decryption examples for CFB mode
const auto decCFB1 = bCrypt.cfb_decrypt(encCFB1.result, secret, e_cfb_algorithm::AES);
std::cout << "CFB/AES Decrypted:        " << decCFB1.result << "\n";
const auto decCFB2 = bCrypt.cfb_decrypt(encCFB2.result, secret, e_cfb_algorithm::BLOWFISH);
std::cout << "CFB/BLOWFISH Decrypted:   " << decCFB2.result << "\n";
const auto decCFB3 = bCrypt.cfb_decrypt(encCFB3.result, secret, e_cfb_algorithm::CAST128);
std::cout << "CFB/CAST128 Decrypted:    " << decCFB3.result << "\n";
const auto decCFB4 = bCrypt.cfb_decrypt(encCFB4.result, secret, e_cfb_algorithm::CAST256);
std::cout << "CFB/CAST256 Decrypted:    " << decCFB4.result << "\n";
const auto decCFB5 = bCrypt.cfb_decrypt(encCFB5.result, secret, e_cfb_algorithm::IDEA);
std::cout << "CFB/IDEA Decrypted:       " << decCFB5.result << "\n";
const auto decCFB6 = bCrypt.cfb_decrypt(encCFB6.result, secret, e_cfb_algorithm::RC2);
std::cout << "CFB/RC2 Decrypted:        " << decCFB6.result << "\n";
const auto decCFB7 = bCrypt.cfb_decrypt(encCFB7.result, secret, e_cfb_algorithm::RC5);
std::cout << "CFB/RC5 Decrypted:        " << decCFB7.result << "\n";

// Encryption examples for OFB mode
const auto encOFB1 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::AES);
std::cout << "AES/OFB Encrypted:        " << encOFB1.result << "\n";
const auto encOFB2 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::BLOWFISH);
std::cout << "BLOWFISH/OFB Encrypted:   " << encOFB2.result << "\n";
const auto encOFB3 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::CAST128);
std::cout << "CAST128/OFB Encrypted:    " << encOFB3.result << "\n";
const auto encOFB4 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::CAST256);
std::cout << "CAST256/OFB Encrypted:    " << encOFB4.result << "\n";
const auto encOFB5 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::IDEA);
std::cout << "IDEA/OFB Encrypted:       " << encOFB5.result << "\n";
const auto encOFB6 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::RC2);
std::cout << "RC2/OFB Encrypted:        " << encOFB6.result << "\n";
const auto encOFB7 = bCrypt.ofb_encrypt(src, secret, e_ofb_algorithm::RC5);
std::cout << "RC5/OFB Encrypted:        " << encOFB7.result << "\n";

// Decryption examples for OFB mode
const auto decOFB1 = bCrypt.ofb_decrypt(encOFB1.result, secret, e_ofb_algorithm::AES);
std::cout << "OFB/AES Decrypted:        " << decOFB1.result << "\n";
const auto decOFB2 = bCrypt.ofb_decrypt(encOFB2.result, secret, e_ofb_algorithm::BLOWFISH);
std::cout << "OFB/BLOWFISH Decrypted:   " << decOFB2.result << "\n";
const auto decOFB3 = bCrypt.ofb_decrypt(encOFB3.result, secret, e_ofb_algorithm::CAST128);
std::cout << "OFB/CAST128 Decrypted:    " << decOFB3.result << "\n";
const auto decOFB4 = bCrypt.ofb_decrypt(encOFB4.result, secret, e_ofb_algorithm::CAST256);
std::cout << "OFB/CAST256 Decrypted:    " << decOFB4.result << "\n";
const auto decOFB5 = bCrypt.ofb_decrypt(encOFB5.result, secret, e_ofb_algorithm::IDEA);
std::cout << "OFB/IDEA Decrypted:       " << decOFB5.result << "\n";
const auto decOFB6 = bCrypt.ofb_decrypt(encOFB6.result, secret, e_ofb_algorithm::RC2);
std::cout << "OFB/RC2 Decrypted:        " << decOFB6.result << "\n";
const auto decOFB7 = bCrypt.ofb_decrypt(encOFB7.result, secret, e_ofb_algorithm::RC5);
std::cout << "OFB/RC5 Decrypted:        " << decOFB7.result << "\n";

// Encryption examples for CTR mode
const auto encCTR1 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::AES);
std::cout << "AES/CTR Encrypted:        " << encCTR1.result << "\n";
const auto encCTR2 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::BLOWFISH);
std::cout << "BLOWFISH/CTR Encrypted:   " << encCTR2.result << "\n";
const auto encCTR3 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::CAST128);
std::cout << "CAST128/CTR Encrypted:    " << encCTR3.result << "\n";
const auto encCTR4 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::CAST256);
std::cout << "CAST256/CTR Encrypted:    " << encCTR4.result << "\n";
const auto encCTR5 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::IDEA);
std::cout << "IDEA/CTR Encrypted:       " << encCTR5.result << "\n";
const auto encCTR6 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::RC2);
std::cout << "RC2/CTR Encrypted:        " << encCTR6.result << "\n";
const auto encCTR7 = bCrypt.ctr_encrypt(src, secret, e_ctr_algorithm::RC5);
std::cout << "RC5/CTR Encrypted:        " << encCTR7.result << "\n";

// Decryption examples for CTR mode
const auto decCTR1 = bCrypt.ctr_decrypt(encCTR1.result, secret, e_ctr_algorithm::AES);
std::cout << "CTR/AES Decrypted:        " << decCTR1.result << "\n";
const auto decCTR2 = bCrypt.ctr_decrypt(encCTR2.result, secret, e_ctr_algorithm::BLOWFISH);
std::cout << "CTR/BLOWFISH Decrypted:   " << decCTR2.result << "\n";
const auto decCTR3 = bCrypt.ctr_decrypt(encCTR3.result, secret, e_ctr_algorithm::CAST128);
std::cout << "CTR/CAST128 Decrypted:    " << decCTR3.result << "\n";
const auto decCTR4 = bCrypt.ctr_decrypt(encCTR4.result, secret, e_ctr_algorithm::CAST256);
std::cout << "CTR/CAST256 Decrypted:    " << decCTR4.result << "\n";
const auto decCTR5 = bCrypt.ctr_decrypt(encCTR5.result, secret, e_ctr_algorithm::IDEA);
std::cout << "CTR/IDEA Decrypted:       " << decCTR5.result << "\n";
const auto decCTR6 = bCrypt.ctr_decrypt(encCTR6.result, secret, e_ctr_algorithm::RC2);
std::cout << "CTR/RC2 Decrypted:        " << decCTR6.result << "\n";
const auto decCTR7 = bCrypt.ctr_decrypt(encCTR7.result, secret, e_ctr_algorithm::RC5);
std::cout << "CTR/RC5 Decrypted:        " << decCTR7.result << "\n";
  return 0;
}
