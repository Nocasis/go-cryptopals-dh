package dh

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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