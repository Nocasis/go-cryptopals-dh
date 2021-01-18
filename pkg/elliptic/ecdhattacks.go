package elliptic

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"math/big"

	"github.com/Nocasis/go-cryptopals-dh/pkg/x128"
)

func genBigNum(max *big.Int) (n *big.Int, err error) {
	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return x, nil
}

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

func maliciousTwistECDH(x *big.Int, possibleKey *big.Int) []byte {
	dataPoint := x128.ScalarMult(x, possibleKey.Bytes())
	return mixKey(dataPoint.Bytes())
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

type twistPoint struct {
	order *big.Int
	point *big.Int
}

func findTwistPoint(r *big.Int, tr *big.Int) *big.Int {
	order := new(big.Int).Div(tr, r)

	for {
		//Choose a random u mod p and verify that u^3 + A*u^2 + u is a nonsquare in GF(p).
		u, _ := genBigNum(x128.P)
		v := new(big.Int).ModSqrt(x128.GetPolynomialValue(u), new(big.Int).Set(x128.P))

		if v == nil {
			//Call the order of the twist n. To find an element of order q, calculate ladder(u, n/q)
			pu := x128.ScalarMult(u, order.Bytes())
			if pu.Cmp(BigZero) == 0 {
				continue
			}
			return pu
		}
	}
}


//findAllPointsOfPrimeOrderOnX128 finds a point with a specified order for u^3 + A*u^2 + u in GF(p).
func findAllPointsOfPrimeOrderOnX128() (points []twistPoint) {
	// It is known, that both curves contain 2*p+2 points: |E| + |T| = 2*p + 2

	//Calculate the order of the twist and find its small factors. This one should have a bunch under 2^24.
	pointsCount := new(big.Int).Add(new(big.Int).Mul(x128.P, BigTwo), BigTwo)
	twistOrder := new(big.Int).Sub(pointsCount, x128.N)
	factors := factorize(twistOrder, 1<<24)
	log.Printf("Factors = %s", factors)
	for i := 0; i < len(factors); i++ {
		r := factors[i]
		u := findTwistPoint(r, twistOrder)
		points = append(points, twistPoint{order: r, point: u})
	}
	return
}

// Alg from this doc https://arxiv.org/pdf/0812.0789.pdf
func calculateK(a *big.Int, b *big.Int) *big.Int {
	tmpLeft := math.Log2(float64(new(big.Int).Sqrt(new(big.Int).Sub(b, a)).Uint64()))
	tmpRight := math.Log2(tmpLeft)
	return new(big.Int).SetUint64(uint64(tmpLeft + tmpRight - 2))
}

// f(y) function from this link https://toadstyle.org/cryptopals/58.txt
func f(y *big.Int, k *big.Int) *big.Int {
	return new(big.Int).Exp(BigTwo, new(big.Int).Mod(y, k), nil) // 2^(y mod k)
}

func calculateBoundsN(k *big.Int) *big.Int {
	N := BigZero
	for i := BigZero; i.Cmp(k) == -1 /* i < k */ ; i = new(big.Int).Add(i, BigOne) {
		N = new(big.Int).Add(N, f(i, k))
	}
	//N is then derived from f - take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4
	N = new(big.Int).Div(N, k)
	return new(big.Int).Mul(big.NewInt(3), N)
}


func tameKangarooOnCurve(curve Curve, bx, by, b, k *big.Int) (*big.Int, *big.Int, *big.Int) {
	log.Printf("Trying to calculate bounds(N)\n")
	N := calculateBoundsN(k)
	log.Printf("N = %s\n", N.String())

	xT := BigZero
	xyT, yyT := curve.ScalarMult(bx, by, b.Bytes())

	for i := BigZero; i.Cmp(N) == -1 /* i < N*/ ; i = new(big.Int).Add(i, BigOne) {
		//log.Printf("i = %s, N = %s\n", i.String(), N.String())
		xT = new(big.Int).Add(xT, f(xyT, k))  // xT + f(xyT)
		x_, y_ := curve.ScalarMult(bx, by, f(xyT, k).Bytes())
		xyT, yyT = curve.Add(xyT, yyT, x_, y_)
	}

	xB, yB := curve.ScalarMult(bx, by, new(big.Int).Add(b, xT).Bytes())
	if xyT.Cmp(xB) != 0 && yyT.Cmp(yB) != 0 {
		log.Fatal("yT != g^(b + xT)")
		return nil, nil, nil
	}
	return xT, xyT, yyT
}

// catchKangarooOnMontgomeryCurve implements Pollard's kangaroo algorithm on a curve.
func catchKangarooOnCurve(curve Curve, bx, by, x, y, a, b *big.Int) (m *big.Int, err error) {
	// k is calculated based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
	log.Printf("Trying to calculate K\n")
	k := calculateK(a, b)
	log.Printf("y = %s, a = %s, b = %s, k = %s\n", y.String(), a.String(), b.String(), k.String())
	log.Printf("Trying to tame Kangaroo\n")
	xT, xyT, yyT := tameKangarooOnCurve(curve, bx, by, b, k)
	log.Printf("tame xT = %s, xyT = %s, yyT = %s\n", xT.String(), xyT.String(), yyT.String())

	xW := BigZero
	xyW := x
	yyW := y

	// xW < b - a + xT
	for xW.Cmp(new(big.Int).Add(new(big.Int).Sub(b, a), xT)) == -1 {
		//log.Printf("wild xW = %s, yW = %s, yT = %s ---- while %s \n", xW.String(), yW.String(), new(big.Int).Add(b, new(big.Int).Sub(xT, xW)).String(), new(big.Int).Add(new(big.Int).Sub(b, a), xT).String())
		xW = new(big.Int).Add(xW, f(xyW, k))   // xW = xW + f(yW)
		x_, y_ := curve.ScalarMult(bx, by, f(xyW, k).Bytes())
		xyW, yyW = curve.Add(xyW, yyW, x_, y_)

		// yW == yT
		if xyW.Cmp(xyT) == 0 {
			m = new(big.Int).Add(b, new(big.Int).Sub(xT, xW)) //  b + xT - xW
			return m, nil
		}
	}
	return nil, fmt.Errorf("this is a probabilistic algorithm, so it's not guaranteed to work. Not this time")
}


// It turns out that some short Weierstrass curves can be converted into Montgomery curves
func convert(u *big.Int) (*big.Int, *big.Int) {
	v := new(big.Int).ModSqrt(x128.GetPolynomialValue(u), new(big.Int).Set(x128.P))
	if v == nil {
		return nil, nil
	}

	// u = x - 178 https://toadstyle.org/cryptopals/60.txt
	x := new(big.Int).Add(u, big.NewInt(178))

	if P128().IsOnCurve(x, v) {
		return x, v
	}

	if P128().IsOnCurve(x, new(big.Int).Neg(v)) {
		return x, new(big.Int).Neg(v)
	}
	return nil, nil
}

func runECDHTwistAttack(ecdh func(x *big.Int) []byte, getPublicKey func() (*big.Int, *big.Int), privateKeyOracle func(*big.Int) *big.Int) (priv *big.Int) {

	points := findAllPointsOfPrimeOrderOnX128()

	for i := 0; i < len(points); i++ {
		log.Printf("POINTS %d %d, ", points[i].order, points[i].point)
	}

	var reducedModes, reducedBases []*big.Int
	for i := 0; i < len(points); i++ {
		point := points[i]

		log.Printf("Point %d\n", point.point)
		data := ecdh(point.point)

		for k := BigOne; k.Cmp(point.order) <= 0 /* k <= r */; k = new(big.Int).Add(k, BigOne) {
			maliciousData := maliciousTwistECDH(point.point, k)
			//log.Printf("maliciousData %s, data %s, k %s, priv %s\n", hex.EncodeToString(maliciousData), hex.EncodeToString(data), k, priv)
			isDuplicate, _ := pairInPairedArrays(reducedModes, reducedBases, point.order, k)
			if bytes.Equal(maliciousData, data) && !isDuplicate {
				log.Printf("Added %s %s \n", point.order.String(), k.String())
				reducedModes = append(reducedModes, point.order)
				reducedBases = append(reducedBases, k)
				break
			}
		}
	}

	log.Printf("bases %s, modes %s", reducedBases, reducedModes)
	x, n, err := crt(reducedBases, reducedModes)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	fmt.Printf("x, n %d, %d", x, n)

	curve := P128()

	publicKey, _ := getPublicKey()
	xNew, yNew := convert(publicKey)
	if xNew == nil || yNew == nil {
		log.Fatal("Error with convert")
		return nil
	}

	bxNew, byNew := curve.ScalarBaseMult(new(big.Int).Neg(x).Bytes())
	xNew, yNew = curve.Add(xNew, yNew, bxNew, byNew)
	a := BigZero
	b := new(big.Int).Div(new(big.Int).Sub(x128.Q, BigOne), n) // [0, (q-1)/r]

	log.Printf("Cathing Kangaroo Alg")
	m, err := catchKangarooOnCurve(curve, bxNew, byNew, xNew, yNew, a, b)
	if err != nil {
		fmt.Print(fmt.Errorf("error: %v", err))
		return nil
	}

	priv = new(big.Int).Add(x, new(big.Int).Mul(m, n))
	return priv
}