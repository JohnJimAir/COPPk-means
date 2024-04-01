package main

import (
	"fmt"
	"goisbest/ciphertext/naive"
	"goisbest/ciphertext/printers"
	"goisbest/ciphertext/signcompare"
	"math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/utils"
)


func main() {

	number := 10
	dimension := 2
	points_dim0 := [10]float64{0.07, 0.16, 0.27, 0.27, 0.34, 0.66, 0.72, 0.76, 0.84, 0.87}
	points_dim1 := [10]float64{0.13, 0.34, 0.14, 0.15, 0.22, 0.65, 0.83, 0.68, 0.83, 0.76}
	center0_dim0 := float64(5.5)
	center0_dim1 := float64(7.4)
	center1_dim0 := float64(7.7)
	center1_dim1 := float64(9.4)



	var err error
	var params hefloat.Parameters

	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            14,                                    // log2(ring degree)
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,                                    // log2(scale)
		}); err != nil {
		panic(err)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := hefloat.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)
	eval := hefloat.NewEvaluator(params, evk)

	LogSlots := params.LogMaxSlots()
	Slots := 1 << LogSlots


	fmt.Printf("============================\n")
	fmt.Printf("GENERATE BOOTSTRAP EVALUATOR\n")
	fmt.Printf("============================\n")

	LogN := 14
	btpParametersLit := bootstrapping.ParametersLiteral{
		// We specify LogN to ensure that both the residual parameters and the bootstrapping parameters
		// have the same LogN. This is not required, but we want it for this example.
		LogN: utils.Pointy(LogN),
		// In this example we need manually specify the number of auxiliary primes (i.e. #Pi) used by the
		// evaluation keys of the bootstrapping circuit, so that the size of LogQP  meets the security target.
		LogP: []int{61, 61, 61, 61},
		// In this example we manually specify the bootstrapping parameters' secret distribution.
		// This is not necessary, but we ensure here that they are the same as the residual parameters.
		Xs: params.Xs(),
	}
	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}
	
	fmt.Println("Generating bootstrapping evaluation keys...")
	evk_boot, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")
	var eval_boot *bootstrapping.Evaluator
	if eval_boot, err = bootstrapping.NewEvaluator(btpParams, evk_boot); err != nil {
		panic(err)
	}



	fmt.Printf("============================\n")
	fmt.Printf("GENERATE INNRESUM EVALUATOR \n")
	fmt.Printf("============================\n")

	batch := 1
	n := Slots
	eval_InnerSum := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batch, n), sk)...))



	fmt.Printf("=======================\n")
	fmt.Printf("ENCRYPT PROVIDED VALUES\n")
	fmt.Printf("=======================\n")
	// encrypt points
	r_a := rand.New(rand.NewSource(0))
	points_dim0_values := make([]float64, params.MaxSlots())
	for i := range points_dim0_values {
		points_dim0_values[i] = r_a.Float64() + 7.5
	}
	for i := 0; i < number; i++ {
		points_dim0_values[i] = points_dim0[i]
	}

	points_dim0_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_dim0_values, points_dim0_pt); err != nil {
		panic(err)
	}
	var points_dim0_ct *rlwe.Ciphertext
	if points_dim0_ct, err = encryptor.EncryptNew(points_dim0_pt); err != nil {
		panic(err)
	}
	printers.PrintPlaintext(points_dim0_ct, encoder, decryptor)
	fmt.Println()


	points_dim1_values := make([]float64, params.MaxSlots())
	for i := range points_dim1_values {
		points_dim1_values[i] = r_a.Float64() + 7.5
	}
	for i := 0; i < number; i++ {
		points_dim1_values[i] = points_dim1[i]
	}

	points_dim1_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_dim1_values, points_dim1_pt); err != nil {
		panic(err)
	}
	var points_dim1_ct *rlwe.Ciphertext
	if points_dim1_ct, err = encryptor.EncryptNew(points_dim1_pt); err != nil {
		panic(err)
	}
	printers.PrintPlaintext(points_dim1_ct, encoder, decryptor)
	fmt.Println()

	points_ct := []*rlwe.Ciphertext{points_dim0_ct, points_dim1_ct}

	

	// encrypt center0
	center0_dim0_values := make([]float64, params.MaxSlots())
	for i := range center0_dim0_values {
		center0_dim0_values[i] = center0_dim0
	}
	center0_dim0_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center0_dim0_values, center0_dim0_pt); err != nil {
		panic(err)
	}
	var center0_dim0_ct *rlwe.Ciphertext
	if center0_dim0_ct, err = encryptor.EncryptNew(center0_dim0_pt); err != nil {
		panic(err)
	}

	center0_dim1_values := make([]float64, params.MaxSlots())
	for i := range center0_dim1_values {
		center0_dim1_values[i] = center0_dim1
	}
	center0_dim1_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center0_dim1_values, center0_dim1_pt); err != nil {
		panic(err)
	}
	var center0_dim1_ct *rlwe.Ciphertext
	if center0_dim1_ct, err = encryptor.EncryptNew(center0_dim1_pt); err != nil {
		panic(err)
	}
	center0_ct := []*rlwe.Ciphertext{center0_dim0_ct, center0_dim1_ct}

	// encrypt center1
	center1_dim0_values := make([]float64, params.MaxSlots())
	for i := range center1_dim0_values {
		center1_dim0_values[i] = center1_dim0
	}
	center1_dim0_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center1_dim0_values, center1_dim0_pt); err != nil {
		panic(err)
	}
	var center1_dim0_ct *rlwe.Ciphertext
	if center1_dim0_ct, err = encryptor.EncryptNew(center1_dim0_pt); err != nil {
		panic(err)
	}

	center1_dim1_values := make([]float64, params.MaxSlots())
	for i := range center1_dim1_values {
		center1_dim1_values[i] = center1_dim1
	}
	center1_dim1_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center1_dim1_values, center1_dim1_pt); err != nil {
		panic(err)
	}
	var center1_dim1_ct *rlwe.Ciphertext
	if center1_dim1_ct, err = encryptor.EncryptNew(center1_dim1_pt); err != nil {
		panic(err)
	}
	center1_ct := []*rlwe.Ciphertext{center1_dim0_ct, center1_dim1_ct}
	


for i:=0;i<11;i++ {

	// fmt.Printf("======================\n")
	// fmt.Printf("===COMPUTE DISTANCE===\n")
	// fmt.Printf("======================\n")
	distances0_ct := naive.ComputeDistance_OnePoint(eval, dimension, points_ct, center0_ct)
	distances1_ct := naive.ComputeDistance_OnePoint(eval, dimension, points_ct, center1_ct)
	// PrintPlaintext(params, distances0_ct, encoder, decryptor)
	// PrintPlaintext(params, distances1_ct, encoder, decryptor)


	// fmt.Printf("======================\n")
	// fmt.Printf("==DISTANCE COMPARISON=\n")
	// fmt.Printf("======================\n")
	bool0_ct, bool1_ct := signcompare.CompareFunction(params, eval, distances0_ct, distances1_ct, eval_boot)
	// PrintPlaintext(params, bool0_ct, encoder, decryptor)
	// PrintPlaintext(params, bool1_ct, encoder, decryptor)
	


	fmt.Printf("==================\n")
	fmt.Printf("==UPDATE CENTERS==\n")
	fmt.Printf("==================\n")
	newCenter0_ct := naive.UpdateCenter_OnePoint(params, eval, number, dimension, points_ct, center0_ct, bool0_ct, eval_InnerSum, batch, n)
	newCenter1_ct := naive.UpdateCenter_OnePoint(params, eval, number, dimension, points_ct, center1_ct, bool1_ct, eval_InnerSum, batch, n)

	printers.PrintPlaintext(newCenter0_ct[0], encoder, decryptor)
	printers.PrintPlaintext(newCenter0_ct[1], encoder, decryptor)
	printers.PrintPlaintext(newCenter1_ct[0], encoder, decryptor)
	printers.PrintPlaintext(newCenter1_ct[1], encoder, decryptor)

	eval.SetScale(newCenter0_ct[0], params.DefaultScale())
	eval.SetScale(newCenter0_ct[1], params.DefaultScale())
	eval.SetScale(newCenter1_ct[0], params.DefaultScale())
	eval.SetScale(newCenter1_ct[1], params.DefaultScale())

	center0_ct[0], err = eval_boot.Bootstrap(newCenter0_ct[0])
	if err != nil {
		panic(err)
	}
	center0_ct[1], err = eval_boot.Bootstrap(newCenter0_ct[1])
	if err != nil {
		panic(err)
	}
	center1_ct[0], err = eval_boot.Bootstrap(newCenter1_ct[0])
	if err != nil {
		panic(err)
	}
	center1_ct[1], err = eval_boot.Bootstrap(newCenter1_ct[1])
	if err != nil {
		panic(err)
	}


	}
}



