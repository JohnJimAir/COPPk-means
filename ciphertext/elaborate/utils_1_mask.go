package elaborate

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func Mask_GetSingleFragment(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location int, length_fragment int) (ciphertext_out *rlwe.Ciphertext) {
	
	var err error
	mask_values := make([]float64, ciphertext_in.Slots()) // 应该不需要params，可以直接从ciphertext获得slots个数
	for i := location * length_fragment; i < (location+1) * length_fragment; i++ {
		mask_values[i] = 1.0
	}

	ciphertext_out, err = eval.MulRelinNew(ciphertext_in, mask_values)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ciphertext_out, ciphertext_out); err != nil {  //这里的rescale是需要的，不像Gaussian integer那样
		panic(err)
	}
	return ciphertext_out
}

func Mask_GetContinuousFragments(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location_start int, num_locations int, length_fragment int) (ciphertext_out *rlwe.Ciphertext) {
	
	var err error
	mask_values := make([]float64, ciphertext_in.Slots()) // 应该不需要params，可以直接从ciphertext获得slots个数
	for i := location_start * length_fragment; i < (location_start+num_locations) * length_fragment; i++ {
		mask_values[i] = 1.0
	}

	ciphertext_out, err = eval.MulRelinNew(ciphertext_in, mask_values)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ciphertext_out, ciphertext_out); err != nil {  //这里的rescale是需要的，不像Gaussian integer那样
		panic(err)
	}
	return ciphertext_out
}

func Mask_GetSpecificSpotInFragment_and_Rescale(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, length_fragment int, location_spot int, num_fragments int, scalar int) (ciphertext_out *rlwe.Ciphertext) {
	
	var err error
	mask_values := make([]float64, ciphertext_in.Slots())
	for i:=0;i<num_fragments;i++ {
		mask_values[location_spot + i*length_fragment] = 1.0/float64(scalar)
	}
	ciphertext_out, err = eval.MulRelinNew(ciphertext_in, mask_values)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(ciphertext_out, ciphertext_out); err != nil {
		panic(err)
	}
	return ciphertext_out
}