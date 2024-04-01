// Package main is a template encrypted arithmetic with floating point values, with a set of example parameters, key generation, encoding, encryption, decryption and decoding.
package main

import (
	"fmt"

	//"math/cmplx"
	"math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
)

func main() {
	var err error
	var params hefloat.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            14,                                    // log2(ring degree)
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,                                    // log2(scale)
		}); err != nil {
		panic(err)
	}

	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)

	// Secret Key
	sk := kgen.GenSecretKeyNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	// Encoder
	ecd := hefloat.NewEncoder(params)

	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)

	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)

	LogSlots := params.LogMaxSlots()
	Slots := 1 << LogSlots

	// Vector of plaintext values
	values := make([]float64, params.MaxSlots())

	// Source for sampling random plaintext values (not cryptographically secure)
	/* #nosec G404 */
	r := rand.New(rand.NewSource(0))

	// Populates the vector of plaintext values
	for i := range values {
		values[i] = 2*r.Float64() - 1 // uniform in [-1, 1]
	}
	values[0] = -6

	// Allocates a plaintext at the max level.
	// Default rlwe.MetaData:
	// - IsBatched = true (slots encoding)
	// - Scale = params.DefaultScale()
	pt := hefloat.NewPlaintext(params, params.MaxLevel())

	// Encodes the vector of plaintext values
	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	// Encrypts the vector of plaintext values
	var ct *rlwe.Ciphertext
	if ct, err = enc.EncryptNew(pt); err != nil {
		panic(err)
	}

	// Allocates a vector for the reference values
	want := make([]float64, params.MaxSlots())
	copy(want, values)

	PrintPrecisionStats(params, ct, want, ecd, dec)

	fmt.Printf("=====================\n")
	fmt.Printf("POLYNOMIAL EVALUATION\n")
	fmt.Printf("=====================\n")
	fmt.Printf("\n")

	SiLU := func(x float64) (y float64) {
		//return 1 / (math.Exp(-x) + 1)
		if x > 0 {
			return 1
		} else if x < 0 {
			return -1
		} else {
			return 0
		}
	}

	prec := params.EncodingPrecision()

	interval := bignum.Interval{
		Nodes: 63,
		A:     *bignum.NewFloat(-8, prec),
		B:     *bignum.NewFloat(8, prec),
	}

	poly := bignum.ChebyshevApproximation(SiLU, interval)

	for i := 0; i < Slots; i++ {
		want[i], _ = poly.Evaluate(values[i])[0].Float64()
	}

	scalarmul, scalaradd := poly.ChangeOfBasis()

	eval := hefloat.NewEvaluator(params, evk)

	res, err := eval.MulNew(ct, scalarmul)
	if err != nil {
		panic(err)
	}

	if err = eval.Add(res, scalaradd, res); err != nil {
		panic(err)
	}

	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	polyEval := hefloat.NewPolynomialEvaluator(params, eval)

	if res, err = polyEval.Evaluate(res, poly, params.DefaultScale()); err != nil {
		panic(err)
	}

	fmt.Printf("Polynomial Evaluation %s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())

	PrintPrecisionStats(params, res, want, ecd, dec)
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params hefloat.Parameters, ct *rlwe.Ciphertext, want []float64, ecd *hefloat.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]float64, params.MaxSlots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", want[i])
	}
	fmt.Printf("...\n")

	// Pretty prints the precision stats
	fmt.Println(hefloat.GetPrecisionStats(params, ecd, dec, have, want, 0, false).String())
}
