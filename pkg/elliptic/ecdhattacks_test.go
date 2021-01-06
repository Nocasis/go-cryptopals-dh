package elliptic

import (
	"fmt"
	"math/big"
	"testing"
)

func TestECDHInvalidCurveAttack(t *testing.T) {
	p128 := P128()

	basePointOrder, _ := new(big.Int).SetString("29246302889428143187362802287225875743", 10)
	ex, ey := p128.ScalarBaseMult(basePointOrder.Bytes())

	if fmt.Sprintf("%d", ex) != "0" || fmt.Sprintf("%d", ey) != "0" {
		t.Fatalf("%s: correction test failed", t.Name())
	}

	// Alice generates a key pair.
	aPriv, ax, ay, _ := GenerateKey(p128, nil)
	// Bob generates a key pair.
	bPriv, bx, by, _ := GenerateKey(p128, nil)

	// Alice runs DH.
	asx, asy := p128.ScalarMult(bx, by, aPriv)
	// Bob runs DH.
	bsx, bsy := p128.ScalarMult(ax, ay, bPriv)

	if asx.Cmp(bsx) != 0 || asy.Cmp(bsy) != 0 {
		t.Errorf("%s: incorrect ECDH", t.Name())
	}

	oracle, isKeyCorrect, _ := newECDHAttackOracle(p128)

	privateKey := runECDHInvalidCurveAttack(oracle)
	t.Logf("%s: Private key:%d", t.Name(), privateKey)

	if !isKeyCorrect(privateKey.Bytes()) {
		t.Fatalf("%s: wrong private key was found in the invalid curve attack", t.Name())
	}
}