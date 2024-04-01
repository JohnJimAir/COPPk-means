package signcompare

import (
	"goisbest/utilities/coefficients"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
)

func SignFuncion(params hefloat.Parameters, ciphertext_in *rlwe.Ciphertext, eval *hefloat.Evaluator, eval_boot *bootstrapping.Evaluator) (ciphertext_out *rlwe.Ciphertext) {
	var err error

	// coeffs := coeffs_n15
	var floatArray [2]float64
	floatArray[0] = -8
	floatArray[1] = 8
	in := floatArray
	poly_3 := bignum.NewPolynomial(0, coefficients.Coeffs_n3, in)
	poly_7 := bignum.NewPolynomial(0, coefficients.Coeffs_n7, in)
	poly_15 := bignum.NewPolynomial(0, coefficients.Coeffs_n15, in)
	polyEval := hefloat.NewPolynomialEvaluator(params, eval)

	ciphertext_in, err = polyEval.Evaluate(ciphertext_in, poly_3, params.DefaultScale())
	if err != nil {
		panic(err)
	}
	ciphertext_in, err = polyEval.Evaluate(ciphertext_in, poly_7, params.DefaultScale())
	if err != nil {
		panic(err)
	}

	ciphertext_in, err = eval_boot.Bootstrap(ciphertext_in)
	if err != nil {
		panic(err)
	}
	for i:=0;i<2;i++ {
		// PrintScaleAndLevel(ciphertextIn)
		// fmt.Println("nnnnnnnnnnn")
		ciphertext_in, err = polyEval.Evaluate(ciphertext_in, poly_15, params.DefaultScale())
		if err != nil {
			panic(err)
		}
		// PrintScaleAndLevel(ciphertextIn)
		// fmt.Println("ooooooooooooo")	
	}
	ciphertext_in, err = eval_boot.Bootstrap(ciphertext_in)
	if err != nil {
		panic(err)
	}

	ciphertext_out = ciphertext_in
	return 
}

func CompareFunction(params hefloat.Parameters, eval *hefloat.Evaluator, ciphertext1_in *rlwe.Ciphertext, ciphertext2_in *rlwe.Ciphertext, eval_boot *bootstrapping.Evaluator) (cciphertext1_out *rlwe.Ciphertext, ciphertext2_out *rlwe.Ciphertext) {
	// be careful of the level of ciphertext1, ciphertext2
	ciphertext_tmp, _ := eval.SubNew(ciphertext1_in, ciphertext2_in)

	ciphertext_tmp = SignFuncion(params, ciphertext_tmp, eval, eval_boot)

	return TransformFormat_SignCompare(eval, ciphertext_tmp)
}

func TransformFormat_SignCompare(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext)(ciphertext1_out *rlwe.Ciphertext, ciphertext2_out *rlwe.Ciphertext){
	
	ciphertext2_out, err := eval.AddNew(ciphertext_in, 1.0)
	if err != nil {
		panic(err)
	}
	ciphertext2_out, err = eval.MulRelinNew(ciphertext2_out, 0.5)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ciphertext2_out, ciphertext2_out); err != nil {
		panic(err)
	}
	
	ciphertext1_out, err = eval.MulRelinNew(ciphertext2_out, -1.0) //乘以Gaussian integer不增加scale, 不用rescale，因为对于Gaussian integer有自动的操作来优化scale和level
	if err != nil {
		panic(err)
	}
	ciphertext1_out, err = eval.AddNew(ciphertext1_out, 1.0)
	if err != nil {
		panic(err)
	}
	return ciphertext1_out, ciphertext2_out
}