// Package x128 implements the insecure Montgomery curve x128 defined in the Cryptopals challange 59.
package x128

import (
	"crypto/rand"
	"io"
	"math/big"
)

var (
	// A  - the a parameter.
	A = big.NewInt(534)
	// N - the order of the base point.
	N, _ = new(big.Int).SetString("233970423115425145498902418297807005944", 10)
	// P - the order of the underlying field.
	P, _ = new(big.Int).SetString("233970423115425145524320034830162017933", 10)
	// Q - the order of the subgroup.
	Q, _ = new(big.Int).SetString("29246302889428143187362802287225875743", 10)
	// U - the base point coordinate.
	U = big.NewInt(4)
	// V - the base point coordinate.
	V, _ = new(big.Int).SetString("85518893674295321206118380980485522083", 10)
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
	four  = big.NewInt(4)
)

func ScalarBaseMult(k []byte) *big.Int {
	return ScalarMult(U, k)
}

func ScalarMult(in *big.Int, k []byte) *big.Int {
	return ladder(in, new(big.Int).SetBytes(k))
}

func IsOnCurve(u, v *big.Int) bool {
	vNew := new(big.Int).Mul(v, v)
	vNew.Mod(vNew, P)
	return getPolynomialValue(u).Cmp(vNew) == 0
}

// returns value of v^2 = u^3 + A*u^2 + u
func getPolynomialValue(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	x3 := new(big.Int).Mul(x2, x)
	aX2 := new(big.Int).Mul(A, x2)
	x3.Add(x3, new(big.Int).Add(aX2, x))
	x3.Mod(x3, P)
	return x3
}

func cswap(x, y *big.Int, b bool) (u, v *big.Int) {
	if b {
		return y, x
	}
	return x, y
}

func ladder(u, k *big.Int) *big.Int {
	u2 , w2 := one, zero //u2, w2 := (1, 0)
	u3 , w3 := new(big.Int).Set(u), one //u3, w3 := (u, 1)

	for i := P.BitLen() - 1; i >= 0; i-- { 	//for i in reverse(range(bitlen(p))):
		b := new(big.Int).And(one, new(big.Int).Rsh(k, uint(i))) //b := 1 & (k >> i)
		u2, u3 = cswap(u2, u3, b.Cmp(one) == 0) //u2, u3 := cswap(u2, u3, b)
		w2, w3 = cswap(w2, w3, b.Cmp(one) == 0) //w2, w3 := cswap(w2, w3, b)

		// u3 := (u2*u3 - w2*w3)^2
		u2u3 := new(big.Int).Mul(u2, u3) // u2*u3
		w2w3 := new(big.Int).Mul(w2, w3) // w2*w3
		u2w3 := new(big.Int).Mul(u2, w3) // u2*w3
		w2u3 := new(big.Int).Mul(w2, u3) // w2*u3
		u3 = new(big.Int).Sub(u2u3, w2w3) // (u2*u3 - w2*w3)
		u3 = new(big.Int).Mul(u3, u3) // ^2
		u3.Mod(u3, P)

		// w3 := u * (u2*w3 - w2*u3)^2`
		w3 = new(big.Int).Sub(u2w3, w2u3) // (u2*w3 - w2*u3)
		w3 = new(big.Int).Mul(w3, w3) // ^2
		w3 = new(big.Int).Mul(w3, u) // *u
		w3.Mod(w3, P)

		// u2 := (u2^2 - w2^2)^2
		u22 := new(big.Int).Mul(u2, u2)
		w22 := new(big.Int).Mul(w2, w2)
		u2w2 := new(big.Int).Mul(u2, w2)
		au2w2 := new(big.Int).Mul(A, u2w2)
		fu2w2 := new(big.Int).Mul(four, u2w2)

		u2 = new(big.Int).Sub(u22, w22)
		u2 = new(big.Int).Mul(u2, u2)
		u2.Mod(u2, P)


		// w2 := 4*u2*w2 * (u2^2 + A*u2*w2 + w2^2)
		w2 = new(big.Int).Add(new(big.Int).Add(u22, w22), au2w2)
		w2 = new(big.Int).Mul(fu2w2, w2)
		w2.Mod(w2, P)

		u2, u3 = cswap(u2, u3, b.Cmp(one) == 0) //u2, u3 := cswap(u2, u3, b)
		w2, w3 = cswap(w2, w3, b.Cmp(one) == 0) //w2, w3 := cswap(w2, w3, b)

	}
	result := new(big.Int).Exp(w2, new(big.Int).Sub(P, two), P)
	result.Mul(u2, result)
	result.Mod(result, P)

	return result
}

func GenerateKey(rng io.Reader) (priv []byte, pub *big.Int, err error) {
	if rng == nil {
		rng = rand.Reader
	}

	bitSize := Q.BitLen()
	byteLen := (bitSize + 7) >> 3
	priv = make([]byte, byteLen)

	for pub == nil {
		_, err = io.ReadFull(rng, priv)
		if err != nil {
			return
		}
		if new(big.Int).SetBytes(priv).Cmp(Q) >= 0 {
			continue
		}

		pub = ScalarBaseMult(priv)
	}
	return
}