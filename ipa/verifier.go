package ipa

import (
	"fmt"

	gnarkbandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/common"
	"math/big"
)

// CheckIPAProof verifies an IPA proof for a committed polynomial in evaluation form.
// It verifies that `proof` is a valid proof for the polynomial at the evaluation
// point `evalPoint` with result `result`
func CheckIPAProof(transcript *common.Transcript, ic *IPAConfig, commitment banderwagon.Element, proof IPAProof, evalPoint fr.Element, result fr.Element) (bool, error) {
	transcript.DomainSep(labelDomainSep)

	if len(proof.L) != len(proof.R) {
		return false, fmt.Errorf("vectors L and R should be the same size")
	}
	if len(proof.L) != int(ic.numRounds) {
		return false, fmt.Errorf("the number of points for L and R should be equal to the number of rounds")
	}

	b := computeBVector(ic, evalPoint)

	transcript.AppendPoint(&commitment, labelC)
	transcript.AppendScalar(&evalPoint, labelInputPoint)
	transcript.AppendScalar(&result, labelOutputPoint)

	w := transcript.ChallengeScalar(labelW)

	//fmt.Printf("w: %v\n", w.ToBigIntRegular(new(big.Int)))

	//PrintPoint("ic.Q", ic.Q.Inner())

	// Rescaling of q.
	var q banderwagon.Element
	q.ScalarMul(&ic.Q, &w)

	//PrintPoint("q", q.Inner())

	var qy banderwagon.Element
	qy.ScalarMul(&q, &result)
	commitment.Add(&commitment, &qy)

	//PrintPoint("commit", commitment.Inner())

	challenges := generateChallenges(transcript, &proof)
	challengesInv := fr.BatchInvert(challenges)

	// Compute expected commitment
	var err error
	for i := 0; i < len(challenges); i++ {
		x := challenges[i]
		L := proof.L[i]
		R := proof.R[i]

		//fmt.Printf("x: %v\n", x.ToBigIntRegular(new(big.Int)))

		//fmt.Printf("x: %v\n",  challengesInv[i].ToBigIntRegular(new(big.Int)))

		commitment, err = commit([]banderwagon.Element{commitment, L, R}, []fr.Element{fr.One(), x, challengesInv[i]})
		if err != nil {
			return false, fmt.Errorf("could not compute commitment+x*L+x^-1*R: %w", err)
		}

		//PrintPoint("commitment", &commitment.Inner)
	}

	//PrintPoint("commitment", commitment.Inner())

	g := ic.SRS

	// We compute the folding-scalars for g and b.
	foldingScalars := make([]fr.Element, len(g))
	for i := 0; i < len(g); i++ {
		scalar := fr.One()
		for challengeIdx := 0; challengeIdx < len(challenges); challengeIdx++ {
			if i&(1<<(7-challengeIdx)) > 0 {
				scalar.Mul(&scalar, &challengesInv[challengeIdx])
			}
		}
		foldingScalars[i] = scalar
	}
	g0, err := MultiScalar(g, foldingScalars)
	if err != nil {
		return false, fmt.Errorf("could not compute g0: %w", err)
	}

	b0, err := InnerProd(b, foldingScalars)
	if err != nil {
		return false, fmt.Errorf("could not compute b0: %w", err)
	}

	//fmt.Printf("b0: %v\n", b0.ToBigIntRegular(new(big.Int)))

	var got banderwagon.Element
	//  g0 * a + (a * b) * Q;
	var part_1 banderwagon.Element

	//PrintPoint("g0", &g0.Inner)
	//fmt.Printf("A_scalar: %v\n", proof.A_scalar.ToBigIntRegular(new(big.Int)))

	part_1.ScalarMul(&g0, &proof.A_scalar)

	//PrintPoint("part_1", &part_1.Inner)

	var part_2 banderwagon.Element
	var part_2a fr.Element

	part_2a.Mul(&b0, &proof.A_scalar)
	part_2.ScalarMul(&q, &part_2a)

	//PrintPoint("part_2", &part_2.Inner)

	got.Add(&part_1, &part_2)

	//PrintPoint("got", &got.Inner)

	//PrintPoint("commitment", &commitment.Inner)

	return got.Equal(&commitment), nil
}

func generateChallenges(transcript *common.Transcript, proof *IPAProof) []fr.Element {

	challenges := make([]fr.Element, len(proof.L))
	for i := 0; i < len(proof.L); i++ {
		transcript.AppendPoint(&proof.L[i], labelL)
		transcript.AppendPoint(&proof.R[i], labelR)
		challenges[i] = transcript.ChallengeScalar(labelX)
	}
	return challenges
}

func PrintPoint(str string, p *gnarkbandersnatch.PointProj) {
	var commitmentAffine gnarkbandersnatch.PointAffine
	commitmentAffine.FromProj(p)
	fmt.Printf("%v: x: %v\n", str, commitmentAffine.X.BigInt(new(big.Int)))
	fmt.Printf("%v: y: %v\n", str, commitmentAffine.Y.BigInt(new(big.Int)))
}

func PrintPointProj(str string, p *gnarkbandersnatch.PointProj) {
	fmt.Printf("%v: x: %v\n", str, p.X.BigInt(new(big.Int)))
	fmt.Printf("%v: y: %v\n", str, p.Y.BigInt(new(big.Int)))
	fmt.Printf("%v: z: %v\n", str, p.Z.BigInt(new(big.Int)))
}
