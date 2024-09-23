An implementation of completely outsourced privacy-preserving k-means clustering based on the FHE scheme CKKS, leveraging bootstrapping of CKKS, from this article: https://eprint.iacr.org/2024/1141

Without interaction in the middle, just send ciphertexts and evaluation keys at first, then the final result in ciphertext state will be send back.

New version is at here: https://github.com/JohnJimAir/COPPk-means_new, with datasets added to make this library self-contained.
