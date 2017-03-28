//
// Created by Vuong Nguyen on 27/03/2017.
//

//Generate an RSA key pair, sign a message and verify it using crypto++ 5.6.1 or later.
// Example code for array sink:
// ++ http://stackoverflow.com/questions/19814236/how-to-encrypt-a-byte-array-with-crypto
//To compile: g++ rsa.cpp -lcryptopp -I /usr/include/cryptopp -o rsa

#include <string>

using namespace std;

#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>

using namespace CryptoPP;

void GenKeyPair(int keySize) {
  // InvertibleRSAFunction is used directly only because the private key
  // won't actually be used to perform any cryptographic operation;
  // otherwise, an appropriate typedef'ed type from rsa.h would have been used.
  AutoSeededRandomPool rng;
  InvertibleRSAFunction privkey;
  privkey.Initialize(rng, keySize);

  // With the current version of Crypto++, MessageEnd() needs to be called
  // explicitly because Base64Encoder doesn't flush its buffer on destruction.
  string privateFile = "rsa_privKey_" + std::to_string(keySize) + ".txt";
  Base64Encoder privkeysink(new FileSink(privateFile.c_str()));
  privkey.DEREncode(privkeysink);
  privkeysink.MessageEnd();

  // Suppose we want to store the public key separately,
  // possibly because we will be sending the public key to a third party.
  RSAFunction pubkey(privkey);

  string publicFile = "rsa_publicKey_" + std::to_string(keySize) + ".txt";
  Base64Encoder pubkeysink(new FileSink(publicFile.c_str()));
  pubkey.DEREncode(pubkeysink);
  pubkeysink.MessageEnd();
}

int main() {
  int keySizeList[] = {256, 512, 1024, 2048, 3072};
  for (int i = 0; i < sizeof(keySizeList); i++) {
    GenKeyPair(keySizeList[i]);
  }
}