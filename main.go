package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)


func genBigNum(max *big.Int) (n *big.Int, err error){
	var x *big.Int
	x, err = rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return x, nil
}

func main() {
	var a *big.Int
	var b *big.Int

	p := big.NewInt(37)
	g := big.NewInt(5)

	var err error
	a, err = genBigNum(p)
	if err != nil {
		fmt.Println("Problem with generating of big number")
		os.Exit(1)
	}

	b, err = genBigNum(p)
	if err != nil {
		fmt.Println("Problem with generating of big number")
		os.Exit(1)
	}

	A := new(big.Int).Exp(g, a, p)
	B := new(big.Int).Exp(g, b, p)
	sessionOne := new(big.Int).Exp(B, a, p)
	sessionTwo := new(big.Int).Exp(A, b, p)
	if sessionOne.Cmp(sessionTwo) == 0{
		fmt.Println("Fine")
	} else {
		fmt.Println("Bad")
	}
}
