package evm

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/foxcool/psina/provider/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Signatures below were produced independently with foundry
// (`cast wallet sign --private-key <key> <message>`) using the well-known
// anvil dev keys, so they pin compatibility with real Ethereum tooling.
const (
	signer      = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" // anvil key #0
	otherSigner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" // anvil key #1

	fullMessage = "app.example.com wants you to sign in with your Ethereum account:\n" +
		signer + "\n" +
		"\n" +
		"Sign in to psina.\n" +
		"\n" +
		"URI: https://app.example.com/login\n" +
		"Version: 1\n" +
		"Chain ID: 1\n" +
		"Nonce: 32891756abcd\n" +
		"Issued At: 2026-10-23T12:00:00Z\n" +
		"Expiration Time: 2026-10-23T12:05:00Z"
	fullMessageSig      = "0xa71246f61e2abdcd96b7f7e79aad4baace4d7efdc135419b75831fc472de4bf806abd37c30db6e91f3940380c0b0718cb9962c1ef563afff0acaa86e621847261b" // v=27
	fullMessageOtherSig = "0xb4d6fa211463c3c4c3d0f2d1250f54ca64be6e37b179b03e6591501d4c4550ed450f23ca46b96c578ee3fe7b15af5b70fe960be2f4c09817e462fdfda144ec641b"

	bareMessage = "app.example.com wants you to sign in with your Ethereum account:\n" +
		signer + "\n" +
		"\n" +
		"\n" +
		"URI: https://app.example.com/login\n" +
		"Version: 1\n" +
		"Chain ID: 137\n" +
		"Nonce: 32891756abce\n" +
		"Issued At: 2026-10-23T12:00:00Z"
	bareMessageSig = "0xdc9b674e0daedaae86d168e55fae63d04fb5e4cdf2e50f6dfcbae7c8bd1289b35825990a9830ca3acab72a2532edb7b14a1207fc528de3bc38453c6ef65315061c" // v=28

	// EIP-191 prefixes the byte length, which differs from the rune count here.
	cyrillicMessage = "app.example.com wants you to sign in with your Ethereum account:\n" +
		signer + "\n" +
		"\n" +
		"Войти в psina.\n" +
		"\n" +
		"URI: https://app.example.com/login\n" +
		"Version: 1\n" +
		"Chain ID: 1\n" +
		"Nonce: 32891756abcf\n" +
		"Issued At: 2026-10-23T12:00:00Z"
	cyrillicMessageSig = "0x96784a934567da8bfae70f87003b6646e027c03c262ae5741a9643072ff633df0e1527cc30d6644782123c91ebf3cbba4a71525fb7b62d34faf2ff3fb822729a1c"
)

func TestNormalizeAddress(t *testing.T) {
	p := New("ethereum", 1)

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		// Checksummed vectors from the EIP-55 specification.
		{name: "eip55 mixed 1", in: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", want: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "eip55 mixed 2", in: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", want: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{name: "eip55 mixed 3", in: "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", want: "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{name: "eip55 mixed 4", in: "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", want: "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
		{name: "eip55 all caps", in: "0x52908400098527886E0F7030069857D2E4169EE7", want: "0x52908400098527886E0F7030069857D2E4169EE7"},
		{name: "eip55 all lower", in: "0xde709f2102306220921060314715629080e2fb77", want: "0xde709f2102306220921060314715629080e2fb77"},
		{name: "lowercase gets checksummed", in: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", want: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "uppercase gets checksummed", in: "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED", want: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{name: "bad checksum", in: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", wantErr: true},
		{name: "no prefix", in: "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", wantErr: true},
		{name: "uppercase prefix", in: "0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", wantErr: true},
		{name: "too short", in: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe", wantErr: true},
		{name: "too long", in: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0", wantErr: true},
		{name: "not hex", in: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.NormalizeAddress(tt.in)
			if tt.wantErr {
				assert.True(t, errors.Is(err, ErrInvalidAddress), "got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildMessage(t *testing.T) {
	issued := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		p     *Provider
		nonce string
		opts  wallet.MessageOpts
		want  string
	}{
		{
			name:  "statement and expiry",
			p:     New("ethereum", 1),
			nonce: "32891756abcd",
			opts: wallet.MessageOpts{
				Domain:    "app.example.com",
				URI:       "https://app.example.com/login",
				Statement: "Sign in to psina.",
				IssuedAt:  issued,
				ExpiresAt: issued.Add(5 * time.Minute),
			},
			want: fullMessage,
		},
		{
			name:  "optional fields omitted",
			p:     New("polygon", 137),
			nonce: "32891756abce",
			opts: wallet.MessageOpts{
				Domain: "app.example.com",
				URI:    "https://app.example.com/login",
				// A non-UTC time is written in UTC.
				IssuedAt: issued.In(time.FixedZone("UTC+7", 7*3600)),
			},
			want: bareMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.p.BuildMessage(signer, tt.nonce, tt.opts))
		})
	}
}

func TestVerifySignature(t *testing.T) {
	p := New("ethereum", 1)

	// The same signature with v as a 0/1 recovery id instead of 27/28.
	withV := func(sig, v string) string { return sig[:len(sig)-2] + v }

	tests := []struct {
		name    string
		addr    string
		message string
		sig     string
		wantErr error
	}{
		{name: "valid, v=27", addr: signer, message: fullMessage, sig: fullMessageSig},
		{name: "valid, v=28", addr: signer, message: bareMessage, sig: bareMessageSig},
		{name: "valid, v=0", addr: signer, message: fullMessage, sig: withV(fullMessageSig, "00")},
		{name: "valid, v=1", addr: signer, message: bareMessage, sig: withV(bareMessageSig, "01")},
		{name: "valid, non-ASCII message", addr: signer, message: cyrillicMessage, sig: cyrillicMessageSig},
		{name: "lowercase address", addr: strings.ToLower(signer), message: fullMessage, sig: fullMessageSig},
		{name: "uppercase hex signature", addr: signer, message: fullMessage, sig: "0x" + strings.ToUpper(fullMessageSig[2:])},

		{name: "signed by another key", addr: signer, message: fullMessage, sig: fullMessageOtherSig, wantErr: ErrInvalidSignature},
		{name: "claimed by another address", addr: otherSigner, message: fullMessage, sig: fullMessageSig, wantErr: ErrInvalidSignature},
		{name: "tampered message", addr: signer, message: strings.Replace(fullMessage, "Chain ID: 1", "Chain ID: 10", 1), sig: fullMessageSig, wantErr: ErrInvalidSignature},
		{name: "wrong recovery id", addr: signer, message: fullMessage, sig: withV(fullMessageSig, "1c"), wantErr: ErrInvalidSignature},
		// 31 and 4 both land on decred's "compressed key, recovery id 0" code
		// and would recover the right key if passed through unchecked.
		{name: "v=31", addr: signer, message: fullMessage, sig: withV(fullMessageSig, "1f"), wantErr: ErrInvalidSignature},
		{name: "v=4", addr: signer, message: fullMessage, sig: withV(fullMessageSig, "04"), wantErr: ErrInvalidSignature},
		{name: "zero r and s", addr: signer, message: fullMessage, sig: "0x" + strings.Repeat("0", 128) + "1b", wantErr: ErrInvalidSignature},
		{name: "too short", addr: signer, message: fullMessage, sig: fullMessageSig[:len(fullMessageSig)-2], wantErr: ErrInvalidSignature},
		{name: "too long", addr: signer, message: fullMessage, sig: fullMessageSig + "00", wantErr: ErrInvalidSignature},
		{name: "no prefix", addr: signer, message: fullMessage, sig: fullMessageSig[2:], wantErr: ErrInvalidSignature},
		{name: "not hex", addr: signer, message: fullMessage, sig: "0x" + strings.Repeat("zz", 65), wantErr: ErrInvalidSignature},
		{name: "empty", addr: signer, message: fullMessage, sig: "", wantErr: ErrInvalidSignature},
		{name: "malformed address", addr: "0x1234", message: fullMessage, sig: fullMessageSig, wantErr: ErrInvalidAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.VerifySignature(tt.addr, tt.message, tt.sig)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.True(t, errors.Is(err, tt.wantErr), "want %v, got %v", tt.wantErr, err)
		})
	}
}

func TestProviderChainIDReachesMessage(t *testing.T) {
	d := wallet.NewDispatcher(New("ethereum", 1), New("polygon", 137))

	p, err := d.Provider("polygon")
	require.NoError(t, err)
	assert.Contains(t, p.BuildMessage(signer, "n0nce123", wallet.MessageOpts{}), "Chain ID: 137")
}
