package corpusreaders

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Known answers from the specifications: the Keccak-256 of the empty string, the
// EIP-3009 TransferWithAuthorization type hash, and the EIP-712 Mail example,
// whose signature by keccak256("cow") recovers to the example's address.
func TestEvmSignatureKnownAnswers(t *testing.T) {
	if got := hex.EncodeToString(keccak256(nil)); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("keccak256(empty) = %s", got)
	}
	typeHash := keccak256([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
	if got := hex.EncodeToString(typeHash); got != "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267" {
		t.Fatalf("TransferWithAuthorization type hash = %s", got)
	}
	digest, _ := hex.DecodeString("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
	sig, _ := hex.DecodeString("4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c")
	got, ok := evmRecover(digest, sig)
	if !ok || got != "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" {
		t.Fatalf("EIP-712 Mail example recovers to %q (%v)", got, ok)
	}
	if !evmLowS(sig) {
		t.Fatal("the EIP-712 Mail example signature is low-s")
	}
	high := append([]byte{}, sig...)
	s := new(big.Int).SetBytes(sig[32:64])
	copy(high[32:64], pad32(new(big.Int).Sub(secpN, s).Bytes()))
	high[64] = 55 - sig[64]
	if evmLowS(high) {
		t.Fatal("the s-flipped twin must read as high-s")
	}
	if again, ok := evmRecover(digest, high); !ok || again != got {
		t.Fatalf("the s-flipped twin recovers to %q, want %q", again, got)
	}
}
