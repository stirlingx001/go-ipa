package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/crate-crypto/go-ipa/bandersnatch"
	"github.com/crate-crypto/go-ipa/bandersnatch/fp"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/msm"
)

func generateRandomPoints(numPoints uint64) ([]banderwagon.Element, []bandersnatch.PointAffine) {
	seed := "eth_verkle_oct_2021"

	var pointsWagon []banderwagon.Element
	var pointsAffine []bandersnatch.PointAffine
	var increment uint64 = 0
	for uint64(len(pointsWagon)) != numPoints {
		digest := sha256.New()
		digest.Write([]byte(seed))

		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, increment)
		digest.Write(b)

		hash := digest.Sum(nil)

		var x fp.Element
		x.SetBytes(hash)

		increment++

		xAsBytes := x.Bytes()
		var pointFound banderwagon.Element
		err := pointFound.SetBytes(xAsBytes[:])
		if err != nil {
			// This point is not in the correct subgroup or on the curve
			continue
		}
		pointsWagon = append(pointsWagon, pointFound)
		var pointAffine bandersnatch.PointAffine
		pointAffine.FromProj(&pointFound.Inner)
		pointsAffine = append(pointsAffine, pointAffine)

	}

	return pointsWagon, pointsAffine
}

func ToAffine(p *bandersnatch.PointProj) *bandersnatch.PointAffine {
	var pointAffine bandersnatch.PointAffine
	pointAffine.FromProj(p)
	return &pointAffine
}

func main() {
	pointsWagon, affinePoints := generateRandomPoints(4)

	scalars := make([]fr.Element, len(pointsWagon))
	for i := 0; i < len(scalars); i++ {
		scalars[i].SetRandom()
	}

	var p bandersnatch.PointProj
	_, err := bandersnatch.MultiExp(&p, affinePoints, scalars, bandersnatch.MultiExpConfig{
		NbTasks:     1,
		ScalarsMont: true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("p: %v\n", ToAffine(&p))

	var p2 bandersnatch.PointProj
	_, err = msm.MultiExp(&p2, affinePoints, scalars, bandersnatch.MultiExpConfig{
		NbTasks:     1,
		ScalarsMont: true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("p: %v\n", ToAffine(&p2))
}
