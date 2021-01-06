package elliptic

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
)

func factorize(toFactor *big.Int, maxIndex int64) []*big.Int {
	var factors []*big.Int
	for i := int64(3); i < maxIndex; i += 2 {
		I := new(big.Int).SetInt64(i)
		if new(big.Int).Mod(toFactor, I).Cmp(BigZero) == 0 {
			factors = append(factors, I)
			for new(big.Int).Mod(toFactor, I).Cmp(BigZero) == 0 {
				toFactor = new(big.Int).Div(toFactor, I)
			}
		}
		if I.Cmp(toFactor) == 1 {
			break
		}
	}
	return factors
}

// Copied from https://github.com/dnkolegov/dhpals/blob/master/dlp.go
// crt finds a solution of the system on m equations using the Chinese Reminder Theorem.
//
// Let n_1, ..., n_m be pairwise coprime (gcd(n_i, n_j) = 1, for different i,j).
// Then the system of m equations:
// x_1 = a_1 mod n_1
// ...
// x_m = a_m mod n_m
// has a unique solution for x modulo N = n_1 ... n_m
func crt(a, n []*big.Int) (*big.Int, *big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, p, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), p, nil
}


func maliciousECDH(x, y *big.Int, curve Curve, priv []byte) []byte {
	sx, sy := curve.ScalarMult(x, y, priv)
	k := append(sx.Bytes(), sy.Bytes()...)
	return mixKey(k)
}

// Suppose the group has order q. Pick some random point and multiply by q/r. If you land on the identity, start over.
func findPoint(r *big.Int, curve Curve) (*big.Int, *big.Int) {
	for {
		x, y := GeneratePoint(curve)
		x, y = curve.ScalarMult(x, y, new(big.Int).Div(curve.Params().N, r).Bytes())
		if x.Cmp(BigZero) == 0 && y.Cmp(BigZero) == 0 {
			continue
		}
		return x, y
	}
}

func pairInPairedArrays(A, B []*big.Int, x, y *big.Int) (bool, error) {
	if len(A) != len(B) {
		return false, fmt.Errorf("array sizes do not match. Details: %d != %d", len(A), len(B))
	}

	size := len(A)

	for i := 0; i < size; i++ {
		if A[i].Cmp(x) == 0 && B[i].Cmp(y) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func runECDHInvalidCurveAttack(ecdh func(x, y *big.Int) []byte) (priv *big.Int) {
	specialCurves :=  []Curve{P128V1(), P128V2(), P128V3()}
	var reducedModes, reducedBases []*big.Int

	for i := 0; i < len(specialCurves); i++ {
		curve := specialCurves[i]
		factors := factorize(curve.Params().N, 1<<16)
		log.Printf("Factorized %d curve. factors = %s", i, factors)
		for j := 0; j < len(factors); j++ {
			r := factors[j]

			x, y := findPoint(r, curve)
			log.Printf("Found point x, y %d, %d", x, y)
			data := ecdh(x, y)

			for k := BigOne; k.Cmp(r) <= 0 /* k <= r */; k = new(big.Int).Add(k, BigOne){
				maliciousData := maliciousECDH(x, y, curve, k.Bytes())

				isDuplicate, _ := pairInPairedArrays(reducedModes, reducedBases, r, k)
				if bytes.Equal(maliciousData, data) && !isDuplicate {
					reducedModes = append(reducedModes, r)
					reducedBases = append(reducedBases, k)
					break
				}
			}
		}
	}

	log.Printf("Multiply all reduced modes")
	mulResult := BigOne
	for i := int64(0); int(i) < len(reducedModes); i++ {
		if reducedModes == nil {
			log.Fatal("Reduced modes is nil")
			return nil
		}
		mulResult = new(big.Int).Mul(reducedModes[i], mulResult)
	}

	log.Printf("Chinese Reminder Theorem")
	log.Printf("reducedBases = %s, reducedModes = %s", reducedBases, reducedModes)
	priv, _, err := crt(reducedBases, reducedModes)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	return
}