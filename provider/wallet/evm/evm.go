// Package evm implements wallet sign-in for EVM chains with Sign-In with
// Ethereum (EIP-4361): EIP-55 addresses and EIP-191 personal_sign signatures.
//
// shortcut: only externally owned accounts are supported; smart-contract
// wallets sign through EIP-1271, which needs an RPC call to the chain
// (personal-7xr2).
package evm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/foxcool/psina/provider/wallet"
)

const (
	addressHexLen  = 40 // 20-byte address as hex digits, without 0x
	signatureBytes = 65 // r (32) || s (32) || v (1)
)

var (
	// ErrInvalidAddress indicates a malformed address or a failed EIP-55 checksum.
	ErrInvalidAddress = errors.New("invalid evm address")

	// ErrInvalidSignature indicates a malformed signature or one that does not
	// recover to the claimed address.
	ErrInvalidSignature = errors.New("invalid evm signature")
)

// Provider verifies SIWE sign-in for one EVM chain. All EVM chains share the
// address and signature scheme and differ only by chain id, so wiring creates
// one Provider per chain (e.g. New("polygon", 137)).
type Provider struct {
	chain   string
	chainID int
}

var _ wallet.WalletProvider = (*Provider)(nil)

// New returns a provider serving chain (the dispatcher key) with the given
// EIP-155 chain id.
func New(chain string, chainID int) *Provider {
	return &Provider{chain: chain, chainID: chainID}
}

// Chain returns the chain identifier this provider serves.
func (p *Provider) Chain() string {
	return p.chain
}

// NormalizeAddress returns the EIP-55 checksummed form of addr. All-lowercase
// and all-uppercase input carries no checksum and is accepted; mixed case must
// match the checksum, which is what catches a mistyped address.
func (p *Provider) NormalizeAddress(addr string) (string, error) {
	digits, ok := strings.CutPrefix(addr, "0x")
	if !ok || len(digits) != addressHexLen {
		return "", fmt.Errorf("%w: want 0x followed by %d hex digits", ErrInvalidAddress, addressHexLen)
	}
	if _, err := hex.DecodeString(digits); err != nil {
		return "", fmt.Errorf("%w: not hex", ErrInvalidAddress)
	}

	lower := strings.ToLower(digits)
	checksummed := checksum(lower)
	if digits != lower && digits != strings.ToUpper(digits) && digits != checksummed[2:] {
		return "", fmt.Errorf("%w: checksum mismatch", ErrInvalidAddress)
	}

	return checksummed, nil
}

// BuildMessage returns the EIP-4361 message for addr, which must already be
// normalized.
func (p *Provider) BuildMessage(addr, nonce string, opts wallet.MessageOpts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s wants you to sign in with your Ethereum account:\n%s\n\n", opts.Domain, addr)
	if opts.Statement != "" {
		b.WriteString(opts.Statement + "\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "URI: %s\nVersion: 1\nChain ID: %d\nNonce: %s\nIssued At: %s",
		opts.URI, p.chainID, nonce, opts.IssuedAt.UTC().Format(time.RFC3339))
	if !opts.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "\nExpiration Time: %s", opts.ExpiresAt.UTC().Format(time.RFC3339))
	}

	return b.String()
}

// VerifySignature checks that sig, a 0x-prefixed 65-byte personal_sign
// signature (r || s || v), signs message with the key behind addr.
func (p *Provider) VerifySignature(addr, message, sig string) error {
	want, err := p.NormalizeAddress(addr)
	if err != nil {
		return err
	}

	compact, err := compactSignature(sig)
	if err != nil {
		return err
	}

	pub, _, err := ecdsa.RecoverCompact(compact, personalSignHash(message))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	got := checksum(hex.EncodeToString(keccak256(pub.SerializeUncompressed()[1:])[12:]))
	if got != want {
		return fmt.Errorf("%w: signed by another address", ErrInvalidSignature)
	}

	return nil
}

// compactSignature turns an Ethereum r || s || v signature into decred's
// compact form v' || r || s, where v' = 27 + recovery id for an uncompressed
// key. Wallets send v as 27/28 (legacy) or 0/1 (some hardware wallets); any
// other value is refused, because e.g. 31 would pass to decred as "compressed
// key" and recover the same signer.
func compactSignature(sig string) ([]byte, error) {
	digits, ok := strings.CutPrefix(sig, "0x")
	if !ok {
		return nil, fmt.Errorf("%w: missing 0x prefix", ErrInvalidSignature)
	}
	raw, err := hex.DecodeString(digits)
	if err != nil || len(raw) != signatureBytes {
		return nil, fmt.Errorf("%w: want %d hex-encoded bytes", ErrInvalidSignature, signatureBytes)
	}

	var code byte
	switch v := raw[signatureBytes-1]; v {
	case 0, 1:
		code = 27 + v
	case 27, 28:
		code = v
	default:
		return nil, fmt.Errorf("%w: recovery id v=%d", ErrInvalidSignature, v)
	}

	return append([]byte{code}, raw[:signatureBytes-1]...), nil
}

// personalSignHash is the EIP-191 version 0x45 hash that personal_sign signs.
func personalSignHash(message string) []byte {
	return keccak256([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)) + message))
}

// checksum applies EIP-55 to 40 lowercase hex digits and adds the 0x prefix:
// a letter is uppercased when the matching nibble of keccak256(digits) is >= 8.
func checksum(lowerDigits string) string {
	hash := keccak256([]byte(lowerDigits))
	out := []byte(lowerDigits)
	for i, c := range out {
		nibble := hash[i/2] >> 4
		if i%2 == 1 {
			nibble = hash[i/2] & 0x0f
		}
		if c >= 'a' && nibble >= 8 {
			out[i] = c - 'a' + 'A'
		}
	}

	return "0x" + string(out)
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
