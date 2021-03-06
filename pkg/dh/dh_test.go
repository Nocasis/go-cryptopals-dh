package dh

import (
	"math/big"
	"testing"
)

func TestEasyDHAttack(t *testing.T) {
	if !sessionMatchTest() {
		t.Error("session keys is not equal")
	}

	if !normalFlowTest() {
		t.Error("normal flow failed")
	}

	if !mitmFlowTest() {
		t.Error("mitm attack failed")
	}

	p, _ := bigFromHex("ffffffffffffffffffffffffffff")
	g := BigOne

	if !maliciousParameterFlowTest(p, g) {
		t.Error("g = 1 attack failed")
	}

	p = big.NewInt(25566665)
	g = big.NewInt(25566665)

	if !maliciousParameterFlowTest(p, g) {
		t.Error("g = p attack failed")
	}

	p = big.NewInt(25566665)
	g = big.NewInt(25566665-1)

	if !maliciousParameterFlowTest(big.NewInt(25566665), big.NewInt(25566665-1)) {
		t.Error("g = p-1 attack failed")
	}
}

func TestSmallSubGroupAttack(t *testing.T) {
	p, _ := bigFromHex("8977c3217da1f838b8d24b4a790de8fc8e35ad5483e463028ef9bbf9af23a9bd1231eba9ac7e44363d8311d610b09aa224a023268ee8a60ac484fd9381962563")
	g, _ := bigFromHex("572aff4a93ec6214c1036c62e1818fe5e4e1d6db635c1b12d9572203c47d241a0e543a89b0b12ba61062411fcf3d29c6ab8c3ce6dac7d2c9f7f0ebd3b7878aaf")
	q, _ := bigFromHex("b1b914de773dfcc8be82251a2ab4f339")
	correctJ, _ := bigFromHex("c603c3a480aeabfebbeace077fcd6f114c33cfd660fa70ee6b2d4859205ee6ea36ca0a2774c44bcd5b41a3fe99428672")
	j := new(big.Int).Div(new(big.Int).Sub(p, BigOne), q)

	if j.Cmp(correctJ) != 0 {
		t.Error("problem with j")
	}
	if new(big.Int).Exp(g, q, p).Cmp(BigOne) != 0 {
		t.Error("g^q != 1")
	}

	if !smallSubGroupAttack(p, g, q, j) {
		t.Error("small subgroup attack failed")
	}
}

//func TestCatchingKangaroosAttackQuick(t *testing.T) {
//	p, _ := bigFromDec("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623")
//	g, _ := bigFromDec("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357")
//	q, _ := bigFromDec("335062023296420808191071248367701059461")
//	qN, _ := bigFromDec("1048576") // For fast test attack. In this case we truncate max value of private key and borders in catching kangaroo algorithm
//	correctJ, _ := bigFromDec("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702")
//	j := new(big.Int).Div(new(big.Int).Sub(p, BigOne), q)
//
//	if j.Cmp(correctJ) != 0 {
//		t.Error("problem with j")
//	}
//	if new(big.Int).Exp(g, q, p).Cmp(BigOne) != 0 {
//		t.Error("g^q != 1")
//	}
//
//	if !catchingKangaroosAttack(p, g, qN, j) {
//		t.Error("catchingKangaroosAttack failed")
//	}
//}

func TestCatchingKangaroosAttack(t *testing.T) {
	p, _ := bigFromDec("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623")
	g, _ := bigFromDec("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357")
	q, _ := bigFromDec("335062023296420808191071248367701059461")
	correctJ, _ := bigFromDec("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702")
	j := new(big.Int).Div(new(big.Int).Sub(p, BigOne), q)

	if j.Cmp(correctJ) != 0 {
		t.Error("problem with j")
	}
	if new(big.Int).Exp(g, q, p).Cmp(BigOne) != 0 {
		t.Error("g^q != 1")
	}

	if !catchingKangaroosAttack(p, g, q, j) {
		t.Error("catchingKangaroosAttack failed")
	}
}

func TestCatchingKangarooAlgorithm(t *testing.T) {
	p, _ := bigFromDec("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623")
	g, _ := bigFromDec("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357")
	y, _ := bigFromDec("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119")
	a := BigZero
	b, _ := bigFromDec("1048576")

	x := catchKangaroo(p, g, y, a, b)
	if x == nil || new(big.Int).Exp(g, x, p).Cmp(y) != 0 {
		t.Error("Catching Kangaroo Algorithm failed")
	}
}
