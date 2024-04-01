// innersum之后再bootstrap得到的结果不对。解决方法是在bootstrap之前，手动对innersum的结果rescale
package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/utils"
)

func main() {

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




	// r_a := rand.New(rand.NewSource(0))
	points_values := make([]float64, params.MaxSlots())
	for i := range points_values {
		points_values[i] =  7.5
	}
	// for i := 0; i < number; i++ {
	// 	points_values[i] = points[i]
	// }

	points_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_values, points_pt); err != nil {
		panic(err)
	}
	var points_ct *rlwe.Ciphertext
	if points_ct, err = encryptor.EncryptNew(points_pt); err != nil {
		panic(err)
	}
	PrintPlaintext(params, points_ct, encoder, decryptor)
	PrintScaleAndLevel(points_ct)
	fmt.Printf("\n")

	points_ct, err = eval_boot.Bootstrap(points_ct)
	if err != nil {
		panic(err)
	}
	PrintPlaintext(params, points_ct, encoder, decryptor)
	PrintScaleAndLevel(points_ct)

	points_ct, err = eval.MulRelinNew(points_ct, 1.0/float64(n))
	if err != nil {
		panic(err)
	}
	if err := eval_InnerSum.InnerSum(points_ct, batch, n, points_ct); err != nil {
		panic(err)
	}
	// rescale之后会有小误差，rescale放在InnerSum之前也会有小误差，很奇怪
	if err = eval.Rescale(points_ct, points_ct); err != nil {
		panic(err)
	}

	PrintPlaintext(params, points_ct, encoder, decryptor)
	PrintScaleAndLevel(points_ct)

	points_ct, err = eval_boot.Bootstrap(points_ct)
	if err != nil {
		panic(err)
	}

	PrintPlaintext(params, points_ct, encoder, decryptor)
	PrintScaleAndLevel(points_ct)

	}

	func PrintPlaintext(params hefloat.Parameters, ciphertext *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor) (values []float64) {

		values = make([]float64, params.MaxSlots())
		if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
			panic(err)
		}

		fmt.Printf("Values: ")
		for i := 0; i < 12; i++ {
			fmt.Printf("%16.15f ", values[i])
		}
		fmt.Printf("...\n")
		return 
	}

	func PrintScaleAndLevel(ciphertext *rlwe.Ciphertext) {
		ctScale := &ciphertext.Scale.Value // We need to access the pointer to have it display correctly in the command line
		fmt.Printf("Scale: %f and Level: %d \n", ctScale, ciphertext.Level())
}