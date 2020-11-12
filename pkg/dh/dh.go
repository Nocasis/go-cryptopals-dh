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

type EntityDH struct {
	privateKey   *big.Int
	publicNum    *big.Int
	power	*big.Int
	generic	*big.Int
}

func (e *EntityDH) init(p *big.Int, g *big.Int) {
	e.power = p
	e.generic = g
	var err error
	e.privateKey, err = genBigNum(p)
	if err != nil {
		log.Fatal("Error with generation of private key")
	}
	e.publicNum = new(big.Int).Exp(e.generic, e.privateKey, e.power)
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
	fmt.Printf("privateKey: %v, publicNum: %v, power: %v, generic: %v.\n", e.privateKey, e.publicNum, e.power, e.generic)
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

	alice := new(EntityDH)
	alice.init(p, g)

	bob := new(EntityDH)
	bob.init(p, g)

	if bytes.Compare(alice.getSessionKey(bob.publicNum), bob.getSessionKey(alice.publicNum)) != 0 {
		return false
	}
	return true
}


type ClientC1 struct {
	dhEntity EntityDH
	aesKey   []byte
}

func (c *ClientC1) init(p *big.Int, g *big.Int) {
	c.dhEntity.init(p, g)
}


func (c *ClientC1) generateSessionKey(pub *big.Int) {
	c.aesKey = c.dhEntity.getSessionKey(pub)[:16]
}

func (c ClientC1) encryptMsg(msg []byte) []byte {
	block, err := aes.NewCipher(c.aesKey)
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

func (c ClientC1) decryptMsg(ciphertext []byte) []byte {
	block, err := aes.NewCipher(c.aesKey)
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
	plaintext := make([]byte, len(ciphertext) - aes.BlockSize)
	mode.CryptBlocks(ciphertext, plaintext)

	return plaintext
}


func (c ClientC1) calcHmacSha256(msg []byte) []byte {
	mac := hmac.New(sha256.New, c.aesKey)
	mac.Write(msg)
	return mac.Sum(nil)
}

func normalFlowTest() bool {
	p := bigFromHex("ffffffffffffffffffffffffffff")
	g := big.NewInt(2)

	alice := new(ClientC1)
	alice.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	alice.generateSessionKey(bob.dhEntity.publicNum)
	bob.generateSessionKey(alice.dhEntity.publicNum)

	msg := []byte("exampleplaintext")

	encryptedByAlice := alice.encryptMsg(msg)
	encryptedByBob := bob.encryptMsg(msg)

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}
	return true
}


func (c ClientC1) melloryDecrypt(ciphertext []byte, seedNum int64) []byte {
	seed := big.NewInt(seedNum)
	h := sha256.New()
	h.Write(seed.Bytes())
	aesKey := h.Sum(nil)[:16]

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
	plaintext := make([]byte, len(ciphertext) - aes.BlockSize)
	mode.CryptBlocks(ciphertext, plaintext)

	return plaintext
}

func mitmFlowTest() bool {
	p := bigFromHex("ffffffffffffffffffffffffffff")
	g := big.NewInt(2)

	alice := new(ClientC1)
	alice.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	mellory := new(ClientC1)

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

	alice := new(ClientC1)
	alice.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	mellory := new(ClientC1)

	alice.generateSessionKey(bob.dhEntity.publicNum)
	bob.generateSessionKey(alice.dhEntity.publicNum)

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
	g:= big.NewInt(25566665)

	alice := new(ClientC1)
	alice.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	mellory := new(ClientC1)

	alice.generateSessionKey(bob.dhEntity.publicNum)
	bob.generateSessionKey(alice.dhEntity.publicNum)

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
	g:= big.NewInt(25566665-1)

	alice := new(ClientC1)
	alice.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	mellory := new(ClientC1)

	alice.generateSessionKey(bob.dhEntity.publicNum)
	bob.generateSessionKey(alice.dhEntity.publicNum)

	msg := []byte("exampleplaintext")

	encryptedByAlice := alice.encryptMsg(msg)
	encryptedByBob := bob.encryptMsg(msg)

	if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
		return false
	}

	if alice.dhEntity.publicNum.Cmp(g) == 0 && bob.dhEntity.publicNum.Cmp(g) == 0 {
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


func factorize(toFactor *big.Int, maxIndex int64) map[int64]int64 {
	factors := make(map[int64]int64)
	var j int64 = 0
	zero := big.NewInt(0)

	for i := int64(2); i < maxIndex; i++ {
		if new(big.Int).Mod(toFactor, big.NewInt(i)).Cmp(zero) == 0 {
			factors[j] = i
			j++
		}
	}
	return factors
}


func calculateH(p *big.Int, r *big.Int) *big.Int{
	power := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), r)
	random, _ := genBigNum(p)
	h := new(big.Int).Exp(random, power, p)
	for h.Cmp(big.NewInt(1)) == 0 {
		random, _ := genBigNum(p)
		h = new(big.Int).Exp(random, power, p)
	}
	return h
}

func smallSubGroupAttack() bool {
	type pair struct {
		base int64
		mode int64
	}
	p := bigFromHex("8977c3217da1f838b8d24b4a790de8fc8e35ad5483e463028ef9bbf9af23a9bd1231eba9ac7e44363d8311d610b09aa224a023268ee8a60ac484fd9381962563")
	g := bigFromHex("572aff4a93ec6214c1036c62e1818fe5e4e1d6db635c1b12d9572203c47d241a0e543a89b0b12ba61062411fcf3d29c6ab8c3ce6dac7d2c9f7f0ebd3b7878aaf")
	q := bigFromHex("b1b914de773dfcc8be82251a2ab4f339")

	if new(big.Int).Exp(g, q, p).Cmp(big.NewInt(1)) != 0 {
		log.Fatal("g^q != 1")
	}
	j := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q)
	//println(j.Int64(), bigFromHex("c603c3a480aeabfebbeace077fcd6f114c33cfd660fa70ee6b2d4859205ee6ea36ca0a2774c44bcd5b41a3fe99428672").Int64())
	if j.Cmp(bigFromHex("c603c3a480aeabfebbeace077fcd6f114c33cfd660fa70ee6b2d4859205ee6ea36ca0a2774c44bcd5b41a3fe99428672")) != 0 {
		log.Fatal("problem with j")
	}

	//maxIndexBig = new(big.Int).Sqrt(toFactor)
	// factors aren't big nums
	factors := factorize(j, int64(65536))


	//for i := 0; i < len(factors); i++ {
	//	println(factors[uint64(i)].Int64())
	//}

	if len(factors) == 0 {
		log.Fatal("empty factors")
	}

	eve := new(ClientC1)
	eve.init(p, g)

	bob := new(ClientC1)
	bob.init(p, g)

	reducedVals := make(map[int64]pair)
	reducedValsSize := int64(0)

	for i := 0; i < len(factors); i++ {
		r := factors[int64(i)]
		h := calculateH(p, big.NewInt(r))

		bob.generateSessionKey(h)

		msg := []byte("exampleplaintext")

		encryptedByBob := bob.encryptMsg(msg)
		msgMac := bob.calcHmacSha256(encryptedByBob)

		for j := int64(0); j < r; j++ {
			seed := new(big.Int).Exp(h, big.NewInt(j), p)
			h := sha256.New()
			h.Write(seed.Bytes())
			sessionKey := h.Sum(nil)[:16]
			mac := hmac.New(sha256.New, sessionKey)
			mac.Write(encryptedByBob)
			if hmac.Equal(msgMac, mac.Sum(nil)) {
				reducedVals[reducedValsSize] = pair{j , r}
				reducedValsSize++
			}
		}
	}

	muls := big.NewInt(1)
	for i := int64(0); int(i) < len(factors); i++ {
		//println(reducedVals[i].base, reducedVals[i].mode)
		muls = new(big.Int).Mul(big.NewInt(reducedVals[i].mode), muls)
	}

	if muls.Cmp(q) == 1 {
		return true
	}


	//if bytes.Compare(alice.decryptMsg(encryptedByBob), bob.decryptMsg(encryptedByAlice)) != 0 {
	//	return false
	//}
	return false
}