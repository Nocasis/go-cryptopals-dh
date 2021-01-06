package dh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"
	"math"
	"math/big"
)

type EntityDH struct {
	privateKey *big.Int
	publicKey  *big.Int
	power      *big.Int
	generic    *big.Int
}

func (e *EntityDH) init(p *big.Int, g *big.Int, q *big.Int) {
	e.power = p
	e.generic = g
	var err error
	if q.Cmp(BigZero) == 0 {
		e.privateKey, err = genBigNum(big.NewInt(math.MaxInt64))
	} else {
		e.privateKey, err = genBigNum(q)
	}
	if err != nil {
		log.Fatal("Error with generation of private key")
	}
	e.publicKey = new(big.Int).Exp(e.generic, e.privateKey, e.power)
}

func (e EntityDH) getSessionKey(pubNum *big.Int) (session []byte) {
	if e.power == nil || e.privateKey == nil {
		log.Fatal("You should initialize first")
	}
	sessionSeed := new(big.Int).Exp(pubNum, e.privateKey, e.power)
	h := sha256.New()
	h.Write(sessionSeed.Bytes())
	session = h.Sum(nil)
	return session
}

func (e EntityDH) debugPrint() {
	log.Printf("privateKey: %v, publicKey: %v, power: %v, generic: %v.\n", e.privateKey, e.publicKey, e.power, e.generic)
}

func sessionMatchTest() bool {
	p := bigFromHex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
		"fffffffffffff")
	g := BigTwo
	q := BigZero

	alice := new(EntityDH)
	alice.init(p, g, q)

	bob := new(EntityDH)
	bob.init(p, g, q)

	if bytes.Equal(alice.getSessionKey(bob.publicKey), bob.getSessionKey(alice.publicKey)) {
		return true
	}
	return false
}

type ClientAes struct {
	dhEntity     EntityDH
	symmetricKey []byte
}

func (c *ClientAes) init(p *big.Int, g *big.Int, q *big.Int) {
	c.dhEntity.init(p, g, q)
}

func (c *ClientAes) generateSessionKey(pub *big.Int) {
	c.symmetricKey = c.dhEntity.getSessionKey(pub)
}

func (c ClientAes) encryptMsg(msg []byte) []byte {
	block, err := aes.NewCipher(c.symmetricKey)
	if err != nil {
		log.Fatal("Error with aes initialization")
	}

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal("Error with iv generation")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)
	return ciphertext
}

func (c ClientAes) decryptMsg(ciphertext []byte) []byte {
	block, err := aes.NewCipher(c.symmetricKey)
	if err != nil {
		log.Fatal("Error with aes initialization")
	}

	if len(ciphertext) < aes.BlockSize {
		log.Fatal("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		log.Fatal("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	mode.CryptBlocks(ciphertext, plaintext)

	return plaintext
}

func (c ClientAes) calcHmacSha256(msg []byte) []byte {
	mac := hmac.New(sha256.New, c.symmetricKey)
	mac.Write(msg)
	return mac.Sum(nil)
}

func normalFlowTest() bool {
	p := bigFromHex("ffffffffffffffffffffffffffff")
	g := BigTwo
	q := BigZero

	alice := new(ClientAes)
	alice.init(p, g, q)

	bob := new(ClientAes)
	bob.init(p, g, q)

	alice.generateSessionKey(bob.dhEntity.publicKey)
	bob.generateSessionKey(alice.dhEntity.publicKey)

	msg := []byte("exampleplaintext")

	encryptedByAlice := alice.encryptMsg(msg)
	encryptedByBob := bob.encryptMsg(msg)

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}
	return true
}

func (c ClientAes) melloryDecrypt(ciphertext []byte, seedNum int64) []byte {
	seed := big.NewInt(seedNum)
	h := sha256.New()
	h.Write(seed.Bytes())
	aesKey := h.Sum(nil)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal("Error with aes initialization")
	}

	if len(ciphertext) < aes.BlockSize {
		log.Fatal("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		log.Fatal("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	mode.CryptBlocks(ciphertext, plaintext)

	return plaintext
}

func mitmFlowTest() bool {
	p := bigFromHex("ffffffffffffffffffffffffffff")
	g := BigTwo
	q := BigZero

	alice := new(ClientAes)
	alice.init(p, g, q)

	bob := new(ClientAes)
	bob.init(p, g, q)

	mellory := new(ClientAes)

	bob.generateSessionKey(p)
	alice.generateSessionKey(p)

	msg := []byte("exampleplaintext")

	encryptedByAlice := alice.encryptMsg(msg)
	encryptedByBob := bob.encryptMsg(msg)

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}
	if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 0)) != 0 {
		return false
	}
	return true
}

func maliciousParameterFlowTest(p *big.Int, g *big.Int) bool {
	q := BigZero

	alice := new(ClientAes)
	alice.init(p, g, q)

	bob := new(ClientAes)
	bob.init(p, g, q)

	mellory := new(ClientAes)

	alice.generateSessionKey(bob.dhEntity.publicKey)
	bob.generateSessionKey(alice.dhEntity.publicKey)

	msg := []byte("exampleplaintext")

	encryptedByAlice := alice.encryptMsg(msg)
	encryptedByBob := bob.encryptMsg(msg)

	if g.Cmp(BigOne) == 0 {
		if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
			return false
		}
		if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 1)) != 0 {
			return false
		}
	}

	if g.Cmp(p) == 0 {
		if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
			return false
		}
		if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 0)) != 0 {
			return false
		}
	}

	if g.Cmp(new(big.Int).Sub(p, BigOne)) == 0 {
		if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
			return false
		}

		if alice.dhEntity.publicKey.Cmp(g) == 0 && bob.dhEntity.publicKey.Cmp(g) == 0 {
			if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 25566665-1)) != 0 {
				return false
			}
		} else {
			if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 1)) != 0 {
				return false
			}
		}
	}

	return true
}

func calculateH(p *big.Int, r *big.Int) *big.Int {
	power := new(big.Int).Div(new(big.Int).Sub(p, BigOne), r)

	h := BigOne
	for h.Cmp(BigOne) == 0 {
		random, _ := genBigNum(p)
		if random.Cmp(BigZero) == 0 {
			random = random.Add(random, BigOne)
		}
		h = new(big.Int).Exp(random, power, p)
	}
	return h
}

func smallSubGroupAttack(p *big.Int, g *big.Int, q *big.Int, toFactor *big.Int) bool {

	// factors aren't big nums
	factors := factorize(toFactor, int64(65536))
	if len(factors) == 0 {
		log.Fatal("empty factors")
	}

	eve := new(ClientAes)
	eve.init(p, g, q)

	bob := new(ClientAes)
	bob.init(p, g, q)

	var reducedModes, reducedBases []*big.Int
	for i := 0; i < len(factors); i++ {
		r := factors[i]

		// Step #1
		h := calculateH(p, r)

		// Step #2,3
		bob.generateSessionKey(h)
		msg := []byte("exampleplaintext")
		encryptedByBob := bob.encryptMsg(msg)
		msgMac := bob.calcHmacSha256(encryptedByBob)

		// Step #4
		for j := int64(1); j <= r.Int64(); j++ {
			seed := new(big.Int).Exp(h, big.NewInt(j), p)
			h := sha256.New()
			h.Write(seed.Bytes())
			sessionKey := h.Sum(nil)
			mac := hmac.New(sha256.New, sessionKey)

			mac.Write(encryptedByBob)
			if hmac.Equal(msgMac, mac.Sum(nil)) {
				reducedModes = append(reducedModes, r)
				reducedBases = append(reducedBases, big.NewInt(j))
				continue
			}
		}
	}

	mulResult := BigOne
	for i := int64(0); int(i) < len(factors); i++ {
		if reducedModes == nil {
			log.Fatal("Reduced modes is nil")
		}
		mulResult = new(big.Int).Mul(reducedModes[i], mulResult)
	}

	if mulResult.Cmp(q) != 1 { // (r1*r2*...*rn) <= q
		log.Fatal("(r1*r2*...*rn) <= q")
		return false
	}

	x, _, err := crt(reducedBases, reducedModes)
	if err != nil {
		log.Fatal("Problem with Chinese Remainder Theorem")
	}
	if bob.dhEntity.privateKey.Cmp(x) == 0 {
		return true
	}

	log.Fatal("Failed in the end of small subgroup attack")
	return false
}

// Alg from this doc https://arxiv.org/pdf/0812.0789.pdf
func calculateK(a *big.Int, b *big.Int) *big.Int {
	tmpLeft := math.Log2(float64(new(big.Int).Sub(b, a).Uint64()))
	tmpRight := math.Log2(tmpLeft)
	return new(big.Int).SetUint64(uint64(tmpLeft + tmpRight - 2))
}

func f(y *big.Int, k *big.Int, p *big.Int) *big.Int {
	return new(big.Int).Exp(BigTwo, new(big.Int).Mod(y, k), p) // 2^(y mod k)
}

func calculateBoundsN(k *big.Int, p *big.Int) *big.Int {
	N := BigZero
	for i := BigZero; i.Cmp(k) == -1 /* i < k */; i = new(big.Int).Add(i, BigOne) {
		N = new(big.Int).Add(N, f(i, k, p))
	}
	//N is then derived from f - take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4
	N = new(big.Int).Div(N, k)
	return new(big.Int).Mul(big.NewInt(3), N)
}

func tameKangaroo(p *big.Int, g *big.Int, b *big.Int, k *big.Int) (*big.Int, *big.Int) {
	log.Printf("Trying to calculate bounds(N)\n")
	N := calculateBoundsN(k, p)
	xT := BigZero
	yT := new(big.Int).Exp(g, b, p) // g^b

	log.Printf("N = %s\n", N.String())
	for i := BigZero; i.Cmp(N) == -1 /* i < N*/; i = new(big.Int).Add(i, BigOne) {
		//log.Printf("i = %s, N = %s\n", i.String(), N.String())
		xT = new(big.Int).Add(xT, f(yT, k, p))                                       // xT + f(yT)
		yT = new(big.Int).Mod(new(big.Int).Mul(yT, new(big.Int).Exp(g, f(yT, k, p), p)), p) // yT * g^f(yT)
	}
	if yT.Cmp(new(big.Int).Exp(g, new(big.Int).Add(b, xT), p)) != 0 { // yT = g^(b + xT)
		log.Fatal("yT != g^(b + xT)")
		return nil, nil
	}

	return xT, yT
}

func catchKangaroo(p *big.Int, g *big.Int, y *big.Int, a *big.Int, b *big.Int) (m *big.Int) {
	log.Printf("Trying to calculate K\n")
	k := calculateK(a, b)
	log.Printf("p = %s, g = %s, y = %s, a = %s, b = %s, k = %s\n", p.String(), g.String(), y.String(), a.String(), b.String(),  k.String())
	log.Printf("Trying to tame Kangaroo\n")
	xT, yT := tameKangaroo(p, g, b, k)
	log.Printf("tame xT = %s, yT = %s\n", xT.String(), yT.String())

	xW := BigZero
	yW := y

	// xW < b - a + xT
	for xW.Cmp(new(big.Int).Add(new(big.Int).Sub(b, a), xT)) == -1 {
		//log.Printf("wild xW = %s, yW = %s, yT = %s ---- while %s \n", xW.String(), yW.String(), new(big.Int).Add(b, new(big.Int).Sub(xT, xW)).String(), new(big.Int).Add(new(big.Int).Sub(b, a), xT).String())
		xW = new(big.Int).Add(xW, f(yW, k, p)) // xW = xW + f(yW)  f(y, k) = 2^(y mod k)
		yW = new(big.Int).Mod(new(big.Int).Mul(yW, new(big.Int).Exp(g, f(yW, k, p), p)), p) // yW = yW * g^f(yW)
		// yW == yT
		if yW.Cmp(yT) == 0 {
			m = new(big.Int).Add(b, new(big.Int).Sub(xT, xW)) //  b + xT - xW
			if y.Cmp(new(big.Int).Exp(g, m, p)) != 0 {
				log.Fatal("This is a probabilistic algorithm, so it's not guaranteed to work. Not this time.")
				return nil
			}
			return m
		}
	}
	return nil
}

func catchingKangaroosAttack(p *big.Int, g *big.Int, q *big.Int, toFactor *big.Int) bool {

	// factors aren't big nums
	factors := factorize(toFactor, int64(65536))
	if len(factors) == 0 {
		log.Fatal("empty factors")
	}

	eve := new(ClientAes)
	eve.init(p, g, q)

	bob := new(ClientAes)
	bob.init(p, g, q)

	var reducedModes, reducedBases []*big.Int
	for i := 0; i < len(factors); i++ {
		r := factors[i]

		h := calculateH(p, r)
		bob.generateSessionKey(h)
		msg := []byte("exampleplaintext")
		encryptedByBob := bob.encryptMsg(msg)
		msgMac := bob.calcHmacSha256(encryptedByBob)

		for j := int64(1); j <= r.Int64(); j++ {
			seed := new(big.Int).Exp(h, big.NewInt(j), p)
			h := sha256.New()
			h.Write(seed.Bytes())
			sessionKey := h.Sum(nil)
			mac := hmac.New(sha256.New, sessionKey)

			mac.Write(encryptedByBob)
			if hmac.Equal(msgMac, mac.Sum(nil)) {
				reducedModes = append(reducedModes, r)
				reducedBases = append(reducedBases, big.NewInt(j))
				continue
			}
		}
	}

	n, r, err := crt(reducedBases, reducedModes)
	if err != nil {
		log.Fatal("Problem with Chinese Remainder Theorem")
	}

	y := bob.dhEntity.publicKey
	gNew := new(big.Int).Exp(g, r, p) // g' = g^r
	yNew := new(big.Int).Mod(new(big.Int).Mul(y, new(big.Int).Exp(g, new(big.Int).Neg(n), p)), p) // y' = y * g^-n
	a := BigZero
	b := new(big.Int).Div(new(big.Int).Sub(q, BigOne), r) // [0, (q-1)/r]

	// if we take small q
	if b.Cmp(BigZero) == 0 {
		b = new(big.Int).SetUint64(1048576) // [0, 2^20]
	}
	m := catchKangaroo(p, gNew, yNew, a, b)
	if m == nil{
		log.Fatal("Problem with catching kangaroo alg")
		return false
	}

	calculatedPrivateKey := new(big.Int).Sub(n, new(big.Int).Mul(m, r)) // pkey = n - m*r
	log.Printf("privateKey = %s, calculatedPrivateKey = %s\n", bob.dhEntity.privateKey.String(), calculatedPrivateKey.String())
	if bob.dhEntity.privateKey.Cmp(calculatedPrivateKey) == 0 {
		return true
	}

	log.Fatal("Failed in the end of catchingKangaroosAttack")
	return false
}
