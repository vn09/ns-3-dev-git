// g++ -g3 -O2 cryptopp-elgamal.cpp -o cryptopp-elgamal -lcryptopp -pthread
// Build command:
// ++ g++ -I /usr/local/include/cryptopp elgamal.cpp -lcryptopp -o elgamal

#include <assert.h>
#include <string>
#include <iostream>

#include <crypto++/osrng.h>
#include <crypto++/cryptlib.h>
#include <crypto++/secblock.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hex.h>

using namespace std;
using namespace CryptoPP;

class ELGAMAL_AODV {
  string privKey;
  string seed;

public:
  ELGAMAL_AODV();
  ELGAMAL_AODV(int keySize);
  string encrypt(const char *plainText);

  string decrypt(const char *cipherText);
};

ELGAMAL_AODV::ELGAMAL_AODV(int keySize) {
  privKey = "elgamal_" + to_string(keySize) + ".der";
  seed = "Seed to be used by public";
}

string ELGAMAL_AODV::encrypt(const char *plainText) {
  RandomPool randPool;
  randPool.IncorporateEntropy((byte *) ELGAMAL_AODV::seed.c_str(), strlen(ELGAMAL_AODV::seed.c_str()));

  ElGamalKeys::PrivateKey privateKey;
  privateKey.Load(FileSource(ELGAMAL_AODV::privKey.c_str(), true).Ref());

  ElGamal::Decryptor decryptor(privateKey);
  ElGamal::Encryptor encryptor(decryptor);

  // Convert string to SecbyteBlock
  string sourceByte(plainText);
  SecByteBlock plainTextByte(reinterpret_cast<const byte *>(sourceByte.data()), sourceByte.size());


  ////////////////////////////////////////////////
  // Encrypt
  // Create cipher text space
  size_t ecl = encryptor.CiphertextLength(sourceByte.size());
  SecByteBlock cipherText(ecl);

  encryptor.Encrypt(randPool, plainTextByte, plainTextByte.size(), cipherText);

  string token;
  HexEncoder hex(new StringSink(token));
  hex.Put(cipherText.data(), cipherText.size());
  hex.MessageEnd();

  return token;
}

string ELGAMAL_AODV::decrypt(const char *hex) {
  RandomPool randPool;
  randPool.IncorporateEntropy((byte *) ELGAMAL_AODV::seed.c_str(), strlen(ELGAMAL_AODV::seed.c_str()));

  ElGamalKeys::PrivateKey privateKey;
  privateKey.Load(FileSource(ELGAMAL_AODV::privKey.c_str(), true).Ref());
  ElGamal::Decryptor decryptor(privateKey);

  StringSource ss(hex, true, new HexDecoder);
  SecByteBlock secCipherText((size_t) ss.MaxRetrievable());
  ss.Get(secCipherText, secCipherText.size());

  // Create recovered text space
  size_t dpl = decryptor.MaxPlaintextLength(secCipherText.size());
  SecByteBlock recovered(dpl);

  DecodingResult result = decryptor.Decrypt(randPool, secCipherText, secCipherText.size(), recovered);
  recovered.resize(result.messageLength);

  string recoveredText(reinterpret_cast<const char *>(recovered.data()), recovered.size());
  return recoveredText;
}

// For testing purpose
//int main(int argc, char *argv[]) {
//  ELGAMAL_AODV elgamal_aodv;
//  string plainText = "Hello world";
//  string cipher = elgamal_aodv.encrypt(plainText.data());
//  string recovered = elgamal_aodv.decrypt(cipher.data());
//
//  assert(recovered == plainText);
//}
