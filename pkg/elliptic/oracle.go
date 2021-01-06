package elliptic

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
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
