pragma circom 2.1.5;

include "./ecies/circuits/encrypt.circom";
include "./ecies/circuits/utils.circom";
include "./ecies/circuits/ecdsa-0xparc/circuits/secp256k1.circom";
include "./keccak-circom/keccak.circom";

template Zanity() {
  signal input r[32];     // Random value (private key)
  signal input x[32];     // X coordinate of recipient's public key
  signal input y[32];     // Y coordinate of recipient's public key
  signal input iv[16];    // Initialization vector for AES-CTR
  signal input s1[0];   // First salt for key derivation
  signal input s2[0];   // Second salt for HMAC
  signal input priv_key[32];   // Plaintext to encrypt

  // Expected outputs from ECIES
  signal output ct_pubkey[2][4];  // Decryption public key
  signal output ct[32];       // Encrypted private key
  signal output ct_hmac[32];      // HMAC for authentication
  signal output vanity_pubkey[2][32];  // Vanity public key

  // ECIES encryption
  component ECIES = Encrypt(32,0,0);
  ECIES.r <== r;
  ECIES.x <== x;
  ECIES.y <== y;
  ECIES.iv <== iv;
  ECIES.s1 <== s1;
  ECIES.s2 <== s2;
  ECIES.pt <== priv_key;

  // Output signals
  ct_pubkey <== ECIES.pubkey;
  ct <== ECIES.ct;
  ct_hmac <== ECIES.hmac;

  component BytesToStrides[3];
  for (var i = 0; i < 3; i++) {
    BytesToStrides[i] = BytesToStrides();
  }
  BytesToStrides[0].in <== priv_key;  // Convert private key
  BytesToStrides[1].in <== x;  // Convert public key X
  BytesToStrides[2].in <== y;  // Convert public key Y

  component PRIV2PUB = ECDSAPrivToPub(64,4);
  PRIV2PUB.privkey <== BytesToStrides[0].out;

  // add pubkeys
  component ADDPUBKEYS = Secp256k1AddUnequal(64,4);
  ADDPUBKEYS.a <== PRIV2PUB.pubkey;
  ADDPUBKEYS.b[0] <== BytesToStrides[1].out;
  ADDPUBKEYS.b[1] <== BytesToStrides[2].out;

  component StridesToBytes[2];
  for (var i = 0; i < 2; i++) {
    StridesToBytes[i] = StridesToBytes();
  }
  StridesToBytes[0].in <== ADDPUBKEYS.out[0];
  StridesToBytes[1].in <== ADDPUBKEYS.out[1];

  vanity_pubkey[0] <== StridesToBytes[0].out;
  vanity_pubkey[1] <== StridesToBytes[1].out;
}

