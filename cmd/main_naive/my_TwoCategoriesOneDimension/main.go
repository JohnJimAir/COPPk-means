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
	points := [10]float64{1.2, 2.7, 2.8, 3.1, 3.3, 7.2, 7.7, 7.9, 8.1, 8.3}
	center0 := float64(7.0)
	center1 := float64(9.0)
	// scalar := float64(100.0)



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
	fmt.Printf("GENERATE INNRESUM EVALUATOR\n")
	fmt.Printf("============================\n")

	batch := 1
	n := Slots
	eval_InnerSum := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batch, n), sk)...))



	fmt.Printf("=======================\n")
	fmt.Printf("ENCRYPT PROVIDED VALUES\n")
	fmt.Printf("=======================\n")
	// encrypt points
	r_a := rand.New(rand.NewSource(0))
	points_values := make([]float64, params.MaxSlots())
	for i := range points_values {
		points_values[i] = r_a.Float64() + 7.5
	}
	for i := 0; i < number; i++ {
		points_values[i] = points[i]
	}

	points_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_values, points_pt); err != nil {
		panic(err)
	}
	var points_ct *rlwe.Ciphertext
	if points_ct, err = encryptor.EncryptNew(points_pt); err != nil {
		panic(err)
	}
	printers.PrintPlaintext(points_ct, encoder, decryptor)
	fmt.Printf("\n")

	// encrypt center0
	center0_values := make([]float64, params.MaxSlots())
	for i := range center0_values {
		center0_values[i] = center0
	}
	center0_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center0_values, center0_pt); err != nil {
		panic(err)
	}
	var center0_ct *rlwe.Ciphertext
	if center0_ct, err = encryptor.EncryptNew(center0_pt); err != nil {
		panic(err)
	}

	// encrypt center1
	center1_values := make([]float64, params.MaxSlots())
	for i := range center1_values {
		center1_values[i] = center1
	}
	center1_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center1_values, center1_pt); err != nil {
		panic(err)
	}
	var center1_ct *rlwe.Ciphertext
	if center1_ct, err = encryptor.EncryptNew(center1_pt); err != nil {
		panic(err)
	}


	for i:=0;i<6;i++ {

	// fmt.Printf("======================\n")
	// fmt.Printf("===COMPUTE DISTANCE===\n")
	// fmt.Printf("======================\n")
	// fmt.Println()

	distances0_ct := naive.ComputeDistance_OneDim(eval, points_ct, center0_ct)
	distances1_ct := naive.ComputeDistance_OneDim(eval, points_ct, center1_ct)


	// fmt.Printf("======================\n")
	// fmt.Printf("==DISTANCE COMPARISON=\n")
	// fmt.Printf("======================\n")

	bool0_ct, bool1_ct := signcompare.CompareFunction(params, eval, distances0_ct, distances1_ct, eval_boot)
	


	fmt.Printf("==================\n")
	fmt.Printf("==UPDATE CENTERS==\n")
	fmt.Printf("==================\n")

	newCenter0_ct := naive.UpdateCenter_OneDim(params, eval, number, points_ct, center0_ct, bool0_ct, eval_InnerSum, batch, n)
	newCenter1_ct := naive.UpdateCenter_OneDim(params, eval, number, points_ct, center1_ct, bool1_ct, eval_InnerSum, batch, n)

	printers.PrintPlaintext(newCenter0_ct, encoder, decryptor)
	printers.PrintPlaintext(newCenter1_ct, encoder, decryptor)

	// PrintScaleAndLevel(newCenter0_ct)
	// PrintScaleAndLevel(newCenter1_ct)
	eval.SetScale(newCenter0_ct, params.DefaultScale())
	// PrintPlaintext(params, newCenter0_ct, encoder, decryptor)
	// PrintScaleAndLevel(newCenter0_ct)

	eval.SetScale(newCenter1_ct, params.DefaultScale())

	center0_ct, err = eval_boot.Bootstrap(newCenter0_ct)
	if err != nil {
		panic(err)
	}
	center1_ct, err = eval_boot.Bootstrap(newCenter1_ct)
	if err != nil {
		panic(err)
	}

	printers.PrintPlaintext(center0_ct, encoder, decryptor)
	printers.PrintPlaintext(center1_ct, encoder, decryptor)

	}

}
