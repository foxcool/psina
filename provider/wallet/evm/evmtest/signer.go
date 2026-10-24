// Package evmtest signs messages like an Ethereum wallet, for tests of code
// that verifies wallet sign-in.
package evmtest

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/foxcool/psina/provider/wallet/evm"
)

// Well-known anvil/hardhat dev keys, published in their docs, so the secret
// scanner is told to skip them. Never fund them.
const (
	Key0 = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 gitleaks:allow
	Key1 = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" // 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 gitleaks:allow
)

// Signer holds a private key and its EIP-55 address.
type Signer struct {
	Address string
	key     *secp256k1.PrivateKey
}

// NewSigner loads a hex private key (no 0x prefix).
func NewSigner(keyHex string) (*Signer, error) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	key := secp256k1.PrivKeyFromBytes(raw)
	// An Ethereum address is the last 20 bytes of keccak256 over the
	// uncompressed public key without its 0x04 prefix; evm adds the checksum.
	addr, err := evm.New("", 0).NormalizeAddress("0x" + hex.EncodeToString(keccak256(key.PubKey().SerializeUncompressed()[1:])[12:]))
	if err != nil {
		return nil, err
	}
	return &Signer{Address: addr, key: key}, nil
}

// Sign returns the personal_sign signature of message: 0x-hex r || s || v
// with v as 27/28.
func (s *Signer) Sign(message string) string {
	hash := keccak256([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)) + message))
	compact := ecdsa.SignCompact(s.key, hash, false) // decred order: v || r || s
	// Ethereum order is r || s || v.
	return "0x" + hex.EncodeToString(append(compact[1:], compact[0]))
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
