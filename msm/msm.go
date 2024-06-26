package msm

import (
	"github.com/crate-crypto/go-ipa/bandersnatch"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"math/big"
)

func MultiExp(p *bandersnatch.PointProj, points []bandersnatch.PointAffine, scalars []fr.Element, config bandersnatch.MultiExpConfig) (*bandersnatch.PointProj, error) {
	bigscalars := make([]*big.Int, len(scalars))
	for i := 0; i < len(scalars); i++ {
		bigscalars[i] = scalars[i].ToBigIntRegular(new(big.Int))
	}
	return myMultiExp(p, points, bigscalars)
}

func myMultiExp(p *bandersnatch.PointProj, points []bandersnatch.PointAffine, scalars []*big.Int) (*bandersnatch.PointProj, error) {
	res := bandersnatch.Identity
	for i := 0; i < len(points); i++ {
		var pProj bandersnatch.PointProj
		pProj.FromAffine(&points[i])
		p2 := mult(&pProj, scalars[i])
		res.Add(&res, p2)
	}
	p.Set(&res)
	return p, nil
}

func mult(point *bandersnatch.PointProj, scalar *big.Int) *bandersnatch.PointProj {
	res := bandersnatch.Identity

	var d bandersnatch.PointProj
	d.Set(point)

	for i := 0; i < scalar.BitLen(); i++ {
		b := scalar.Bit(i)
		if b == 1 {
			res.Add(&res, &d)
		}
		if i < scalar.BitLen()-1 {
			d.Double(&d)
		}
	}
	return &res
}
