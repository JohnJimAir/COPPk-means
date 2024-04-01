package elaborate

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func ExpandSpotsDownwards_Continuous_Fast(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, length int) (ciphertext_out *rlwe.Ciphertext) {

	var err error
	if length == 1 {  // 终止条件 length==1 就返回本身
		return ciphertext_in
	} else if length == 0 {  // powerof2 已经完全覆盖掉了，rotate后得到的ciphertext_tmp是不需要的，所以应该置为0
		ct_0, err := eval.MulRelinNew(ciphertext_in, 0)  // 乘以0不消耗level
		if err != nil {
			panic(err)
		}
		return ct_0
	}

	length_powerof2_smaller := GetPowerof2_SmallerOrEqual(length)
	ciphertext_tmp := RotateRight_OneSpot_GivenSteps_OnceDone(eval, ciphertext_in, length_powerof2_smaller)
	ciphertext_out, err = eval.AddNew(ExpandSpotsDownwards_Continuous_Fast_PowerOf2(eval, ciphertext_in, length_powerof2_smaller), 
										ExpandSpotsDownwards_Continuous_Fast(eval, ciphertext_tmp, length-length_powerof2_smaller))
	if err != nil {
		panic(err)
	}
	return ciphertext_out
}

func ExpandSpotsDownwards_Continuous_Fast_PowerOf2(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, length_powerof2 int) (ciphertext_out *rlwe.Ciphertext) {
	
	var err error
	steps_powerof2 := length_powerof2 / 2
	ciphertext_tmp := RotateRight_OneSpot_GivenSteps_OnceDone(eval, ciphertext_in, steps_powerof2)
	ciphertext_in, err = eval.AddNew(ciphertext_in, ciphertext_tmp)
	if err != nil {
		panic(err)
	}
	for steps_powerof2 >=2 {
		steps_powerof2 /= 2
		ciphertext_tmp = RotateRight_OneSpot_GivenSteps_OnceDone(eval, ciphertext_in, steps_powerof2)
		ciphertext_in, err = eval.AddNew(ciphertext_in, ciphertext_tmp)
		if err != nil {
			panic(err)
		}
	}
	ciphertext_out = ciphertext_in
	return ciphertext_out
}