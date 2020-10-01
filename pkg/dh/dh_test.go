package dh

import (
	"math/big"
	"testing"
)

func TestDH(t *testing.T) {
	var a *big.Int
	var b *big.Int

	p := big.NewInt(37)
	g := big.NewInt(5)

	var err error
	a, err = genBigNum(p)
	if err != nil {
		t.Error("Error with generation of a")
	}

	b, err = genBigNum(p)
	if err != nil {
		t.Error("Error with generation of b")
	}

	A := new(big.Int).Exp(g, a, p)
	B := new(big.Int).Exp(g, b, p)
	sessionOne := new(big.Int).Exp(B, a, p)
	sessionTwo := new(big.Int).Exp(A, b, p)
	if sessionOne.Cmp(sessionTwo) != 0{
		t.Error("session keys is not equal")
	}
}