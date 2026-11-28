package corpusreaders

// EVM signature primitives with the standard library only, for the readers of
// corpora that carry EIP-712 signatures: Keccak-256 with the original padding
// (not FIPS 202 SHA3-256), secp256k1 public-key recovery from a 65-byte
// r || s || v signature, and the EIP-712 digest of an EIP-3009
// TransferWithAuthorization. They mirror packaging/agent_evidence_vectors/evmsig.py
// and only recover: no key is held here.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"strings"
)

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [5][5]uint{
	{0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56}, {27, 20, 39, 8, 14},
}

func rol64(v uint64, n uint) uint64 { return v<<n | v>>(64-n) }

func keccakF(a *[5][5]uint64) {
	for _, rc := range keccakRC {
		var c, d [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ rol64(c[(x+1)%5], 1)
		}
		var b [5][5]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y][(2*x+3*y)%5] = rol64(a[x][y]^d[x], keccakRot[x][y])
			}
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				a[x][y] = b[x][y] ^ (^b[(x+1)%5][y] & b[(x+2)%5][y])
			}
		}
		a[0][0] ^= rc
	}
}

// keccak256 is Keccak-256 with the 0x01 domain byte Ethereum uses.
func keccak256(data []byte) []byte {
	const rate = 136
	padded := append(append([]byte{}, data...), 0x01)
	for len(padded)%rate != 0 {
		padded = append(padded, 0)
	}
	padded[len(padded)-1] |= 0x80
	var a [5][5]uint64
	for off := 0; off < len(padded); off += rate {
		for i := 0; i < rate/8; i++ {
			a[i%5][i/5] ^= binary.LittleEndian.Uint64(padded[off+8*i:])
		}
		keccakF(&a)
	}
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], a[i%5][i/5])
	}
	return out
}

var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	secpHalf  = new(big.Int).Rsh(secpN, 1)
)

// A nil *ecPoint is the point at infinity.
type ecPoint struct{ x, y *big.Int }

func ecAdd(a, b *ecPoint) *ecPoint {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	p := secpP
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(a.y, b.y), p).Sign() == 0 {
			return nil
		}
	}
	var lam *big.Int
	if a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 {
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		den := new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), a.y), p)
		lam = new(big.Int).Mod(new(big.Int).Mul(num, den), p)
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(b.x, a.x), p), p)
		lam = new(big.Int).Mod(new(big.Int).Mul(num, den), p)
	}
	x := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lam, lam), a.x), b.x), p)
	y := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(a.x, x)), a.y), p)
	return &ecPoint{x, y}
}

func ecMul(k *big.Int, pt *ecPoint) *ecPoint {
	var result *ecPoint
	addend := pt
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = ecAdd(result, addend)
		}
		addend = ecAdd(addend, addend)
	}
	return result
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// evmAddress is the EIP-55 checksummed address of a public key.
func evmAddress(pt *ecPoint) string {
	raw := append(pad32(pt.x.Bytes()), pad32(pt.y.Bytes())...)
	return evmChecksum(hex.EncodeToString(keccak256(raw)[12:]))
}

func evmChecksum(plain string) string {
	plain = strings.ToLower(strings.TrimPrefix(plain, "0x"))
	digest := hex.EncodeToString(keccak256([]byte(plain)))
	var b strings.Builder
	b.WriteString("0x")
	for i, c := range plain {
		if digest[i] >= '8' && c >= 'a' {
			b.WriteRune(c - 32)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// evmSplit returns r, s and the recovery id of a 65-byte signature whose v is
// 27 or 28 and whose r and s lie in [1, n-1].
func evmSplit(sig []byte) (*big.Int, *big.Int, uint, bool) {
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return nil, nil, 0, false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
		return nil, nil, 0, false
	}
	return r, s, uint(sig[64] - 27), true
}

// evmLowS reports EIP-2's rule: an s above n/2 is a second encoding of a signature.
func evmLowS(sig []byte) bool {
	_, s, _, ok := evmSplit(sig)
	return ok && s.Cmp(secpHalf) <= 0
}

// evmRecover returns the checksummed address whose key made the signature.
func evmRecover(digest, sig []byte) (string, bool) {
	r, s, recid, ok := evmSplit(sig)
	if !ok {
		return "", false
	}
	p := secpP
	alpha := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Exp(r, big.NewInt(3), p), big.NewInt(7)), p)
	exp := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2)
	beta := new(big.Int).Exp(alpha, exp, p)
	if new(big.Int).Mod(new(big.Int).Mul(beta, beta), p).Cmp(alpha) != 0 {
		return "", false
	}
	y := beta
	if beta.Bit(0) != recid {
		y = new(big.Int).Sub(p, beta)
	}
	e := new(big.Int).Mod(new(big.Int).SetBytes(digest), secpN)
	negE := new(big.Int).Mod(new(big.Int).Neg(e), secpN)
	rInv := new(big.Int).ModInverse(r, secpN)
	q := ecMul(rInv, ecAdd(ecMul(s, &ecPoint{r, y}), ecMul(negE, &ecPoint{secpGx, secpGy})))
	if q == nil {
		return "", false
	}
	return evmAddress(q), true
}

var (
	evmAddressRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	evmBytes32Re = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	evmUintRe    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	evmChainRe   = regexp.MustCompile(`^eip155:([1-9][0-9]{0,18})$`)
	twoTo256     = new(big.Int).Lsh(big.NewInt(1), 256)
)

func evmUint(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok || !evmUintRe.MatchString(s) {
		return nil, errors.New("not a uint256")
	}
	n, _ := new(big.Int).SetString(s, 10)
	if n.Cmp(twoTo256) >= 0 {
		return nil, errors.New("not a uint256")
	}
	return pad32(n.Bytes()), nil
}

func evmAddressWord(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok || !evmAddressRe.MatchString(s) {
		return nil, errors.New("not an address")
	}
	b, _ := hex.DecodeString(s[2:])
	return pad32(b), nil
}

// eip3009Digest is the EIP-712 digest of a TransferWithAuthorization under the
// token domain (name, version, chainId of an eip155 network, verifyingContract).
func eip3009Digest(auth map[string]any, network, asset, name, version any) ([]byte, error) {
	net, _ := network.(string)
	m := evmChainRe.FindStringSubmatch(net)
	if m == nil {
		return nil, errors.New("not an eip155 network")
	}
	nameS, ok1 := name.(string)
	versionS, ok2 := version.(string)
	if !ok1 || !ok2 {
		return nil, errors.New("token domain name or version is not a string")
	}
	contract, err := evmAddressWord(asset)
	if err != nil {
		return nil, err
	}
	chain, _ := evmUint(m[1])
	domainType := keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	domain := keccak256(concatBytes(domainType, keccak256([]byte(nameS)), keccak256([]byte(versionS)), chain, contract))
	structType := keccak256([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
	parts := [][]byte{structType}
	for _, field := range []string{"from", "to"} {
		word, err := evmAddressWord(auth[field])
		if err != nil {
			return nil, err
		}
		parts = append(parts, word)
	}
	for _, field := range []string{"value", "validAfter", "validBefore"} {
		word, err := evmUint(auth[field])
		if err != nil {
			return nil, err
		}
		parts = append(parts, word)
	}
	nonce, ok := auth["nonce"].(string)
	if !ok || !evmBytes32Re.MatchString(nonce) {
		return nil, errors.New("nonce is not a bytes32")
	}
	nonceBytes, _ := hex.DecodeString(nonce[2:])
	parts = append(parts, nonceBytes)
	message := keccak256(concatBytes(parts...))
	return keccak256(concatBytes([]byte{0x19, 0x01}, domain, message)), nil
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
