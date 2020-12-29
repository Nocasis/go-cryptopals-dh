package dh

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func genBigNum(max *big.Int) (n *big.Int, err error){
	var x *big.Int
	x, err = rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return x, nil
}

func bigFromHex(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

func factorize(toFactor *big.Int, maxIndex int64) []*big.Int {
	var factors []*big.Int
	zero := big.NewInt(0)

	for i := int64(2); i < maxIndex; i++ {
		I := new(big.Int).SetInt64(i)
		if new(big.Int).Mod(toFactor, I).Cmp(zero) == 0 {
			factors = append(factors, I)
			for new(big.Int).Mod(toFactor, I).Cmp(zero) == 0 {
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