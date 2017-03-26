//Generate an RSA key pair, sign a message and verify it using crypto++ 5.6.1 or later.
// Example code for array sink:
// ++ http://stackoverflow.com/questions/19814236/how-to-encrypt-a-byte-array-with-crypto
//By Tim Sheerman-Chase, 2013
//This code is in the public domain and CC0
//To compile: g++ rsa.cpp -lcryptopp -I /usr/include/cryptopp -o rsa

#include <string>

using namespace std;

#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/hex.h>

using namespace CryptoPP;

class RSA_AODV {
  char privFileName[128] = "privKey.txt";
  char pubFileName[128] = "pubKey.txt";
  char seed[256] = "Seed to be used by public";

public:
  string encrypt(const char *plainText);

  string decrypt(const char *cipherText);
};

string RSA_AODV::encrypt(const char *plainText) {
  FileSource pubFile(RSA_AODV::pubFileName, true, new Base64Decoder);
  RSAES_OAEP_SHA_Encryptor pub(pubFile);

  RandomPool randPool;
  randPool.IncorporateEntropy((byte *) RSA_AODV::seed, strlen(RSA_AODV::seed));

  std::string result;
  StringSource ss1(plainText, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));

  return result;
}

string RSA_AODV::decrypt(const char *cipherText) {
  RandomPool randPool;
  randPool.IncorporateEntropy((byte *) RSA_AODV::seed, strlen(RSA_AODV::seed));

  FileSource privFile(RSA_AODV::privFileName, true, new Base64Decoder);
  RSAES_OAEP_SHA_Decryptor priv(privFile);

  std::string result;
  StringSource ss2(cipherText, true, new HexDecoder(new PK_DecryptorFilter(randPool, priv, new StringSink(result))));

  return result;
}

// For testing purpose
//int main() {
//  RSA_AODV rsa_aodv;
//  char plainText[1024] = "Hello world";
//  string cipherText = rsa_aodv.encrypt(plainText);
//  cout << cipherText;
//
//  string recovered = rsa_aodv.decrypt(cipherText.c_str());
//  assert(recovered == plainText);
//}