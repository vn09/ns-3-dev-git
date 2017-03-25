// g++ -g3 -O2 cryptopp-elgamal.cpp -o cryptopp-elgamal -lcryptopp -pthread
// Build command:
// ++ g++ -I /usr/local/include/cryptopp elgamal.cpp -lcryptopp -o elgamal

#include <assert.h>

#include <iostream>

using std::cout;
using std::cerr;
using std::endl;

#include <crypto++/osrng.h>
#include <crypto++/cryptlib.h>
#include <crypto++/secblock.h>
#include <crypto++/elgamal.h>

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SecByteBlock;
using CryptoPP::ElGamal;
using CryptoPP::ElGamalKeys;

using CryptoPP::DecodingResult;
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

int main(int argc, char *argv[]) {
    ////////////////////////////////////////////////
    // Generate keys
    AutoSeededRandomPool rng;

    cout << "Generating private key. This may take some time..." << endl;

    // ElGamalKeys::PrivateKey pk;
    // pk.GenerateRandomWithKeySize(rng, 2048);
    // ElGamal::Decryptor d(pk);

    ElGamal::Decryptor decryptor;
    decryptor.AccessKey().GenerateRandomWithKeySize(rng, 2048);
    const ElGamalKeys::PrivateKey &privateKey = decryptor.AccessKey();

    // ElGamalKeys::PublicKey pk;
    // privateKey.MakePublicKey(pk);
    // ElGamal::Encryptor e(pk);

    ElGamal::Encryptor encryptor(decryptor);
    const PublicKey &publicKey = encryptor.AccessKey();

    ////////////////////////////////////////////////
    // Secret to protect
    static const int SECRET_SIZE = 16;
    SecByteBlock plaintext(SECRET_SIZE);
    memset(plaintext, 'A', SECRET_SIZE);

    ////////////////////////////////////////////////
    // Encrypt

    // Now that there is a concrete object, we can validate
    assert(0 != encryptor.FixedMaxPlaintextLength());
    assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

    // Create cipher text space
    size_t ecl = encryptor.CiphertextLength(plaintext.size());
    assert(0 != ecl);
    SecByteBlock ciphertext(ecl);

    encryptor.Encrypt(rng, plaintext, plaintext.size(), ciphertext);

    ////////////////////////////////////////////////
    // Decrypt

    // Now that there is a concrete object, we can check sizes
    assert(0 != decryptor.FixedCiphertextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
    assert(0 != dpl);
    SecByteBlock recovered(dpl);

    DecodingResult result = decryptor.Decrypt(rng, ciphertext, ciphertext.size(), recovered);

    // More sanity checks
    assert(result.isValidCoding);
    assert(result.messageLength <=
           decryptor.MaxPlaintextLength(ciphertext.size()));

    // At this point, we can set the size of the recovered
    //  data. Until decryption occurs (successfully), we
    //  only know its maximum size
    recovered.resize(result.messageLength);

    // SecByteBlock is overloaded for proper results below
    assert(plaintext == recovered);
}
