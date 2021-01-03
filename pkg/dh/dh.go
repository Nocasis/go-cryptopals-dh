package dh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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
	if q.Cmp(big.NewInt(0)) == 0 {
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
	fmt.Printf("privateKey: %v, publicKey: %v, power: %v, generic: %v.\n", e.privateKey, e.publicKey, e.power, e.generic)
}

func sessionCmpTest() bool {
	p := bigFromHex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
		"fffffffffffff")
	g := big.NewInt(2)
	q := big.NewInt(0)

	alice := new(EntityDH)
	alice.init(p, g, q)

	bob := new(EntityDH)
	bob.init(p, g, q)

	if bytes.Equal(alice.getSessionKey(bob.publicKey), bob.getSessionKey(alice.publicKey)) {
		return false
	}
	return true
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
	g := big.NewInt(2)
	q := big.NewInt(0)

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
	g := big.NewInt(2)
	q := big.NewInt(0)

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

func g1FlowTest() bool {
	p := bigFromHex("ffffffffffffffffffffffffffff")
	g := big.NewInt(1)
	q := big.NewInt(0)

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

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}
	if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 1)) != 0 {
		return false
	}
	return true
}

func gpFlowTest() bool {
	p := big.NewInt(25566665)
	g := big.NewInt(25566665)
	q := big.NewInt(0)

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

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}
	if bytes.Compare(alice.decryptMsg(encryptedByBob), mellory.melloryDecrypt(encryptedByBob, 0)) != 0 {
		return false
	}
	return true
}

func gp1FlowTest() bool {
	p := big.NewInt(25566665)
	g := big.NewInt(25566665 - 1)
	q := big.NewInt(0)

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

	return true
}

func calculateH(p *big.Int, r *big.Int) *big.Int {
	power := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), r)

	h := big.NewInt(1)
	for h.Cmp(big.NewInt(1)) == 0 {
		random, _ := genBigNum(p)
		if random.Cmp(big.NewInt(0)) == 0 {
			random = random.Add(random, big.NewInt(1))
		}
		h = new(big.Int).Exp(random, power, p)
	}
	return h
}

func smallSubGroupAttack() bool {
	p := bigFromHex("8977c3217da1f838b8d24b4a790de8fc8e35ad5483e463028ef9bbf9af23a9bd1231eba9ac7e44363d8311d610b09aa224a023268ee8a60ac484fd9381962563")
	g := bigFromHex("572aff4a93ec6214c1036c62e1818fe5e4e1d6db635c1b12d9572203c47d241a0e543a89b0b12ba61062411fcf3d29c6ab8c3ce6dac7d2c9f7f0ebd3b7878aaf")
	q := bigFromHex("b1b914de773dfcc8be82251a2ab4f339")

	if new(big.Int).Exp(g, q, p).Cmp(big.NewInt(1)) != 0 {
		log.Fatal("g^q != 1")
	}
	j := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q)
	if j.Cmp(bigFromHex("c603c3a480aeabfebbeace077fcd6f114c33cfd660fa70ee6b2d4859205ee6ea36ca0a2774c44bcd5b41a3fe99428672")) != 0 {
		log.Fatal("problem with j")
	}

	// factors aren't big nums
	factors := factorize(j, int64(65536))
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

	one := big.NewInt(1)
	for i := int64(0); int(i) < len(factors); i++ {
		if reducedModes == nil {
			log.Fatal("Reduced modes is nil")
		}
		//fmt.Printf("ri = %d , bi = %d\n", reducedModes[i].Uint64(), reducedBases[i].Uint64())
		one = new(big.Int).Mul(reducedModes[i], one)
	}

	if one.Cmp(q) != 1 { // (r1*r2*...*rn) <= q
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
