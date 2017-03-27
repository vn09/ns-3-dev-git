//
// Created by Vuong Nguyen on 27/03/2017.
//

// g++ -g3 -O2 cryptopp-elgamal.cpp -o cryptopp-elgamal -lcryptopp -pthread
// Build command:
// ++ g++ -I /usr/local/include/cryptopp elgamal.cpp -lcryptopp -o elgamal

#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/elgamal.h>
#include <cryptopp/cryptlib.h>
#include <crypto++/files.h>

using namespace CryptoPP;
using namespace std;

void generateKey(int keySize) {
  // Generate keys
  AutoSeededRandomPool rng;

  ElGamalKeys::PrivateKey privateKey1;
  privateKey1.GenerateRandomWithKeySize(rng, keySize);

  string fileName = "elgamal_" + to_string(keySize) + ".der";
  privateKey1.Save(FileSink(fileName.c_str(), true).Ref());

}

int main(int argc, char *argv[]) {
  int keySizeList[] = {256, 512, 1024, 2048};
  for (int i = 0; i < 4; i++) {
    generateKey(keySizeList[i]);
  }
}
