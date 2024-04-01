package main

import (
	"flag"
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")

func main() {



	var err error

	flag.Parse()
	LogN := 16
	if *flagShort {
		LogN -= 3
	}
	
	var params hefloat.Parameters
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            LogN,                                              // Log2 of the ring degree
			LogQ:            []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}, // Log2 of the ciphertext prime moduli
			LogP:            []int{61, 61, 61},                                 // Log2 of the key-switch auxiliary prime moduli
			LogDefaultScale: 40,                                                // Log2 of the scale
			Xs:              ring.Ternary{H: 192},
			RingType:        0,
		}); err != nil {
		panic(err)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := hefloat.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	// decryptor := rlwe.NewDecryptor(params, sk)
	eval := hefloat.NewEvaluator(params, evk)

	// LogSlots := params.LogMaxSlots()
	// Slots := 1 << LogSlots


	fmt.Printf("============================\n")
	fmt.Printf("GENERATE BOOTSTRAP EVALUATOR\n")
	fmt.Printf("============================\n")

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
	// get three simple ciphertexts
	ct0_values := make([]float64, params.MaxSlots())
	for i := 0; i < len(ct0_values); i++ {
		ct0_values[i] = 0.6
	}
	ct0_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(ct0_values, ct0_pt); err != nil {
		panic(err)
	}
	ct0_ct, err := encryptor.EncryptNew(ct0_pt)
	if err != nil {
		panic(err)
	}

	ct1_values := make([]float64, params.MaxSlots())
	for i := 0; i < len(ct1_values); i++ {
		ct1_values[i] = 2.4
	}
	ct1_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(ct1_values, ct1_pt); err != nil {
		panic(err)
	}
	ct1_ct, err := encryptor.EncryptNew(ct1_pt)
	if err != nil {
		panic(err)
	}

	ct2_values := make([]float64, params.MaxSlots())
	for i := 0; i < len(ct2_values); i++ {
		ct2_values[i] = 5.4
	}
	ct2_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(ct2_values, ct2_pt); err != nil {
		panic(err)
	}
	ct2_ct, err := encryptor.EncryptNew(ct2_pt)
	if err != nil {
		panic(err)
	}

	// multiply with ct0_ct to consume one level
	ct1_ct, err = eval.MulRelinNew(ct1_ct, ct0_ct)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ct1_ct, ct1_ct); err != nil {  
		panic(err)
	}

	ct2_ct, err = eval.MulRelinNew(ct2_ct, ct0_ct)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ct2_ct, ct2_ct); err != nil {
		panic(err)
	}

	// use goroutines to bootstrap in parallel
	cts := []*rlwe.Ciphertext{ct1_ct, ct2_ct}
	for i:=0;i<len(cts);i++ {
		fmt.Println(cts[i].Level())
	}
	var wg sync.WaitGroup
	for i:=0;i<len(cts);i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval_boot := eval_boot.ShallowCopy()
			fmt.Println(eval_boot.BootstrappingParameters.N())
			cts[i], err = eval_boot.Bootstrap(cts[i])
			if err != nil {
				panic(err)
			}
			fmt.Println("pppppppppppppppp")
		}(i)
	}
	wg.Wait()
	fmt.Println("00000000000000000000000")
	for i:=0;i<len(cts);i++ {
		fmt.Println(cts[i].Level())
		fmt.Println(cts[i].Slots())
	}	

}