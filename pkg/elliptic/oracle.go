package elliptic


import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/Nocasis/go-cryptopals-dh/pkg/x128"
	"math/big"
)

const (
	dhKeyAgreementConst = "crazy flamboyant for the rap enjoyment"
)

func mixKey(k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(dhKeyAgreementConst))
	return mac.Sum(nil)
}

func newECDHAttackOracle(curve Curve) (
	ecdh func(x, y *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (sx, sy *big.Int),
) {

	priv, x, y, err := GenerateKey(curve, nil)
	fmt.Printf("Private key:%d\n", new(big.Int).SetBytes(priv))
	if err != nil {
		panic(err)
	}

	ecdh = func(x, y *big.Int) []byte {
		sx, sy := curve.ScalarMult(x, y, priv)
		k := append(sx.Bytes(), sy.Bytes()...)
		return mixKey(k)
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(priv, key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return x, y
	}

	return
}

func newX128TwistAttackOracle() (
	ecdh func(x *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (*big.Int, *big.Int),
	privateKeyOracle func(*big.Int) *big.Int,
) {

	priv, pub, err := x128.GenerateKey(nil)
	fmt.Printf("Private key:%d\n", new(big.Int).SetBytes(priv))
	if err != nil {
		panic(err)
	}

	ecdh = func(x *big.Int) []byte {
		sx := x128.ScalarMult(x, priv)
		return mixKey(sx.Bytes())
	}

	isKeyCorrect = func(key []byte) bool {
		return bytes.Equal(priv, key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return pub, new(big.Int).SetBytes(priv)
	}

	privateKeyOracle = func(q *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).SetBytes(priv), q)
	}

	return ecdh, isKeyCorrect, getPublicKey, privateKeyOracle
}