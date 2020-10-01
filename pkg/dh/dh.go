package dh

import (
	"crypto/rand"
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
