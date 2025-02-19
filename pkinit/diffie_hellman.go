package pkinit

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

var (
	// DiffieHellmanPrime is the Diffie Hellman prime (P) that is acccepted by PKINIT.
	DiffieHellmanPrime = big.NewInt(0)
	// DiffieHellmanPrime is the Diffie Hellman base (G) that is acccepted by PKINIT.
	DiffieHellmanBase = big.NewInt(2)
)

func init() {
	pBytes, err := hex.DecodeString(
		"00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020b" +
			"bea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe135" +
			"6d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb" +
			"5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff")
	if err != nil {
		panic(fmt.Sprintf("decode Diffie-Hellman parameter p: %v", err))
	}

	DiffieHellmanPrime.SetBytes(pBytes)
}

// DiffieHellmanPublicKey derives the Diffie Hellman public key from the
// provided private key with the parameters that are accepted by PKINIT.
func DiffieHellmanPublicKey(privateKey *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(DiffieHellmanBase, privateKey, DiffieHellmanPrime)

	return publicKey
}

// DiffieHellmanSharedSecret derives the Diffie Hellman shared secret with the
// parameters that are accepted by PKINIT.
func DiffieHellmanSharedSecret(privateKey *big.Int, publicKey *big.Int) *big.Int {
	sharedSecret := new(big.Int).Exp(publicKey, privateKey, DiffieHellmanPrime)

	return sharedSecret
}
