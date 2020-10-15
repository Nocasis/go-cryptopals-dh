package dh

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/aes"
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