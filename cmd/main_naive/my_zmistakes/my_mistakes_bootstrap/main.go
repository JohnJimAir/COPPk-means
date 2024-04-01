// bootstrap的密文slot值受到bootstrap参数的限制，不能过大，不然会出错
package main

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/utils"
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
	// sk := kgen.GenSecretKeyNew()
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	// Encoder
	encoder := hefloat.NewEncoder(params)
	// Encryptor
	// encryptor := rlwe.NewEncryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)
	// Decryptor
	decryptor := rlwe.NewDecryptor(params, sk)

	LogSlots := params.LogMaxSlots()
	Slots := 1 << LogSlots


	fmt.Printf("=====================\n")
	fmt.Printf("==ORIGINAL VALUES a =\n")
	fmt.Printf("=====================\n")
	// Source for sampling random plaintext values (not cryptographically secure)1
	/* #nosec G404 */
	r_a := rand.New(rand.NewSource(0))
	values_a := make([]float64, params.MaxSlots())
	for i := range values_a {
		values_a[i] = 2.0* r_a.Float64() -1.0 // uniform in [-1, 1]
	}
	values_a[0] = 0.012

	// Allocates a plaintext at the max level.
	// Default rlwe.MetaData:
	// - IsBatched = true (slots encoding)
	// - Scale = params.DefaultScale()
	plaintext_a := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(values_a, plaintext_a); err != nil {
		panic(err)
	}
	var ciphertext_a *rlwe.Ciphertext
	if ciphertext_a, err = encryptor.EncryptNew(plaintext_a); err != nil {
		panic(err)
	}

	PrintPrecisionStats(params, ciphertext_a, values_a, encoder, decryptor)
	fmt.Printf("\n")


	fmt.Printf("=====================\n")
	fmt.Printf("==ORIGINAL VALUES b =\n")
	fmt.Printf("=====================\n")
	// Source for sampling random plaintext values (not cryptographically secure)1
	/* #nosec G404 */
	r_b := rand.New(rand.NewSource(1))
	values_b := make([]float64, params.MaxSlots())
	for i := range values_b {
		values_b[i] = 2.0* r_b.Float64() - 1.0 // uniform in [-1, 1]
	}

	// Allocates a plaintext at the max level.
	// Default rlwe.MetaData:
	// - IsBatched = true (slots encoding)
	// - Scale = params.DefaultScale()
	plaintext_b := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(values_b, plaintext_b); err != nil {
		panic(err)
	}
	var ciphertext_b *rlwe.Ciphertext
	if ciphertext_b, err = encryptor.EncryptNew(plaintext_b); err != nil {
		panic(err)
	}

	PrintPrecisionStats(params, ciphertext_b, values_b, encoder, decryptor)
	fmt.Printf("\n")

	// 将两个ciphertext变成为适合于sign函数的单个ciphertext，相减
	fmt.Printf("=====================\n")
	fmt.Printf(" ORIGINAL VALUES a-b \n")
	fmt.Printf("=====================\n")

	valuesTest0 := make([]float64, params.MaxSlots())
	for i := range valuesTest0 {
		valuesTest0[i] = values_a[i] - values_b[i]
	}

	eval := hefloat.NewEvaluator(params, evk)
	ciphertext0, err := eval.SubNew(ciphertext_a, ciphertext_b)
	if err != nil {
		panic(err)
	}
	PrintPrecisionStats(params, ciphertext0, valuesTest0, encoder, decryptor)
	fmt.Println()


	
	fmt.Printf("===========================\n")
	fmt.Printf("FIRST POLYNOMIAL EVALUATION\n")
	fmt.Printf("===========================\n")
	
	// coeffs := []float64{
	// 	0.0,
	// 	2.1875,
	// 	0,
	// 	-2.1875,
	// 	0,
	// 	1.3125,
	// 	0,
	// 	-0.3125,
	// }

	// coeffs := []float64{
	// 	0.0,
	// 	2.4609,
	// 	0,
	// 	-3.2815,
	// 	0,
	// 	2.9531,
	// 	0,
	// 	-1.40625,
	// 	0,
	// 	0.2734,
	// }

	coeffs := []float64{
		0.0,
		315.0/128,
		0.0,
		-420.0/128,
		0.0,
		378.0/128,
		0.0,
		-180.0/128,
		0.0,
		35.0/128,
	}
	//prec := params.EncodingPrecision()
	// interval := bignum.Interval{
	// 	Nodes: 63,
	// 	A:     *bignum.NewFloat(-8, prec),
	// 	B:     *bignum.NewFloat(8, prec),
	// }
	// in := &interval
	var floatArray [2]float64
	floatArray[0] = -8
	floatArray[1] = 8
	in := floatArray
	poly := bignum.NewPolynomial(0, coeffs, in)

	for i := 0; i < Slots; i++ {
		valuesTest0[i], _ = poly.Evaluate(valuesTest0[i])[0].Float64()
	}

	// eval := hefloat.NewEvaluator(params, evk)
	polyEval := hefloat.NewPolynomialEvaluator(params, eval)

	if ciphertext0, err = polyEval.Evaluate(ciphertext0, poly, params.DefaultScale()); err != nil {
		panic(err)
	}

	// fmt.Printf("Polynomial Evaluation %s", hefloat.GetPrecisionStats(params, encoder, decryptor, want, res, 0, false).String())
	PrintPrecisionStats(params, ciphertext0, valuesTest0, encoder, decryptor)
	fmt.Printf("\n")



	fmt.Printf("=====================\n")
	fmt.Printf("=FIRST BOOTSTARPPING=\n")
	fmt.Printf("=====================\n")

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
	// Instantiates the bootstrapper
	var eval_boot *bootstrapping.Evaluator
	if eval_boot, err = bootstrapping.NewEvaluator(btpParams, evk_boot); err != nil {
		panic(err)
	}

	ciphertext1 := ciphertext0
	plaintext1 := decryptor.DecryptNew(ciphertext1)
	valuesWant1 := make([]float64, params.MaxSlots())
	if err = encoder.Decode(plaintext1, valuesWant1); err != nil {
		panic(err)
	}

	fmt.Println("Bootstrapping...")
	ciphertext2, err := eval_boot.Bootstrap(ciphertext1)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")
	fmt.Println()

	valuesTest2 := printDebug(params, ciphertext2, valuesWant1, decryptor, encoder)
	fmt.Printf("\n")


	
	fmt.Printf("============================\n")
	fmt.Printf("SECOND POLYNOMIAL EVALUATION\n")
	fmt.Printf("============================\n")
	for i := 0; i < Slots; i++ {
		valuesTest2[i], _ = poly.Evaluate(valuesTest2[i])[0].Float64()
	}
	if ciphertext2, err = polyEval.Evaluate(ciphertext2, poly, params.DefaultScale()); err != nil {
		panic(err)
	}
	// fmt.Printf("Polynomial Evaluation %s", hefloat.GetPrecisionStats(params, encoder, decryptor, valuesTest2, ciphertext2, 0, false).String())
	PrintPrecisionStats(params, ciphertext2, valuesTest2, encoder, decryptor)
	fmt.Println()

	pt := decryptor.DecryptNew(ciphertext2)
	res := make([]float64, params.MaxSlots())
	if err = encoder.Decode(pt, res); err != nil {
		panic(err)
	}
	max := res[0]
	min := res[0]
	for i := 0; i < Slots; i++ {
		if max < res[i] {max = res[i]}
		if min > res[i] {min = res[i]}
	}
	fmt.Printf("%20.15f\n %20.15f\n 注意有绝对值很大的slot值, 会导致bootstrap出错! 可能得需要改变bootstrap的参数来容纳更大的值!", max, min)
	fmt.Println()



	fmt.Printf("=====================\n")
	fmt.Printf("SECOND BOOTSTARPPING\n")
	fmt.Printf("=====================\n")

	plaintext2 := decryptor.DecryptNew(ciphertext2) //在bootstrap之前才能解密成功
	valuesWant2 := make([]float64, params.MaxSlots())
	if err = encoder.Decode(plaintext2, valuesWant2); err != nil {
		panic(err)
	}

	fmt.Println("Bootstrapping...")
	ciphertext3, err := eval_boot.Bootstrap(ciphertext2)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")
	fmt.Println()

	valuesTest3 := printDebug(params, ciphertext3, valuesWant2, decryptor, encoder)
	fmt.Printf("\n")


	fmt.Printf("============================\n")
	fmt.Printf("THIRD POLYNOMIAL EVALUATION\n")
	fmt.Printf("============================\n")
	for i := 0; i < Slots; i++ {
		valuesTest3[i], _ = poly.Evaluate(valuesTest3[i])[0].Float64()
	}
	if ciphertext3, err = polyEval.Evaluate(ciphertext3, poly, params.DefaultScale()); err != nil {
		panic(err)
	}
	// fmt.Printf("Polynomial Evaluation %s", hefloat.GetPrecisionStats(params, encoder, decryptor, valuesTest2, ciphertext2, 0, false).String())
	PrintPrecisionStats(params, ciphertext3, valuesTest3, encoder, decryptor)
	fmt.Println()



	fmt.Printf("=====================\n")
	fmt.Printf("=THIRD BOOTSTARPPING=\n")
	fmt.Printf("=====================\n")

	plaintext3 := decryptor.DecryptNew(ciphertext3) //在bootstrap之前才能解密成功
	valuesWant3 := make([]float64, params.MaxSlots())
	if err = encoder.Decode(plaintext3, valuesWant3); err != nil {
		panic(err)
	}

	fmt.Println("Bootstrapping...")
	ciphertext4, err := eval_boot.Bootstrap(ciphertext3)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")
	fmt.Println()

	valuesTest4 := printDebug(params, ciphertext4, valuesWant3, decryptor, encoder)
	fmt.Printf("\n")


	fmt.Printf("============================\n")
	fmt.Printf("FOURTH POLYNOMIAL EVALUATION\n")
	fmt.Printf("============================\n")
	for i := 0; i < Slots; i++ {
		valuesTest4[i], _ = poly.Evaluate(valuesTest4[i])[0].Float64()
	}
	if ciphertext4, err = polyEval.Evaluate(ciphertext4, poly, params.DefaultScale()); err != nil {
		panic(err)
	}
	// fmt.Printf("Polynomial Evaluation %s", hefloat.GetPrecisionStats(params, encoder, decryptor, valuesTest2, ciphertext2, 0, false).String())
	PrintPrecisionStats(params, ciphertext4, valuesTest4, encoder, decryptor)
	fmt.Println()

}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params hefloat.Parameters, ciphertext *rlwe.Ciphertext, want []float64, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor) {

	var err error

	// Decrypts the veciphertext0or of plaintext values
	plaintext := decryptor.DecryptNew(ciphertext)
	// Decodes the plaintext
	have := make([]float64, params.MaxSlots())
	if err = encoder.Decode(plaintext, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 6; i++ {
		fmt.Printf("%20.15f ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 6; i++ {
		fmt.Printf("%20.15f ", want[i])
	}
	fmt.Printf("...\n")

	// Pretty prints the precision stats
	// fmt.Println(hefloat.GetPrecisionStats(params, encoder, decryptor, have, want, 0, false).String())
}

func printDebug(params hefloat.Parameters, ciphertext *rlwe.Ciphertext, valuesWant []float64, decryptor *rlwe.Decryptor, encoder *hefloat.Encoder) (valuesTest []float64) {

	valuesTest = make([]float64, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), valuesTest); err != nil {
		panic(err)
	}

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale.Float64()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3], valuesTest[4], valuesTest[5])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3], valuesWant[4], valuesWant[5])

	// precStats := hefloat.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, 0, false)
	// fmt.Println(precStats.String())
	// fmt.Println()

	return
}