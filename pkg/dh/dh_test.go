package dh

import (
	"log"
	"math/big"
	"testing"
)

func TestEasyDHAttack(t *testing.T) {
	if !sessionCmpTest() {
		t.Error("session keys is not equal")
	}

	if !normalFlowTest() {
		t.Error("normal flow failed")
	}

	if !mitmFlowTest() {
		t.Error("mitm attack failed")
	}

	if !g1FlowTest() {
		t.Error("g==1 attack failed")
	}

	if !gpFlowTest() {
		t.Error("g==p attack failed")
	}

	if !gp1FlowTest() {
		t.Error("g==p-1 attack failed")
	}
}

func TestSmallSubGroupAttack(t *testing.T) {
	p := bigFromHex("8977c3217da1f838b8d24b4a790de8fc8e35ad5483e463028ef9bbf9af23a9bd1231eba9ac7e44363d8311d610b09aa224a023268ee8a60ac484fd9381962563")
	g := bigFromHex("572aff4a93ec6214c1036c62e1818fe5e4e1d6db635c1b12d9572203c47d241a0e543a89b0b12ba61062411fcf3d29c6ab8c3ce6dac7d2c9f7f0ebd3b7878aaf")
	q := bigFromHex("b1b914de773dfcc8be82251a2ab4f339")
	j := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q)
	if j.Cmp(bigFromHex("c603c3a480aeabfebbeace077fcd6f114c33cfd660fa70ee6b2d4859205ee6ea36ca0a2774c44bcd5b41a3fe99428672")) != 0 {
		log.Fatal("problem with j")
	}
	if new(big.Int).Exp(g, q, p).Cmp(big.NewInt(1)) != 0 {
		log.Fatal("g^q != 1")
	}

	if !smallSubGroupAttack(p, g, q, j) {
		t.Error("small subgroup attack failed")
	}
}
