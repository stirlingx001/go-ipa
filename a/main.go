package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	"math/big"
)

func main() {
	p1 := bandersnatch.PointProj{
		X: [4]uint64{0, 0, 0, 0},
		Y: [4]uint64{8589934590, 6378425256633387010, 11064306276430008309, 1739710354780652911},
		Z: [4]uint64{8589934590, 6378425256633387010, 11064306276430008309, 1739710354780652911},
	}

	var p1Aff bandersnatch.PointAffine
	p1Aff.FromProj(&p1)

	fmt.Printf("p1 IsOnCurve: %v\n", p1Aff.IsOnCurve())

	scalar, _ := new(big.Int).SetString("129642587988178282529040130059139592623", 10)

	p2 := new(bandersnatch.PointProj).ScalarMultiplication(&p1, scalar)
	fmt.Printf("p2: %v\n", p2)

	var p2Aff bandersnatch.PointAffine
	p2Aff.FromProj(p2)
	fmt.Printf("p2 IsOnCurve: %v\n", p2Aff.IsOnCurve())
}
