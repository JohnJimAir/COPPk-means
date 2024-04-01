package elaborate

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func Rotate_GivenSteps(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, step int, length_fragment int, ) (ciphertext_out *rlwe.Ciphertext) {
	
	if step == 0 {
		return ciphertext_in
	} else if step > 0 {
		return RotateLeft_GivenSteps(eval, ciphertext_in, step, length_fragment)
	} else {
		return RotateRight_GivenSteps(eval, ciphertext_in, -step, length_fragment)
	}
}

func RotateLeft_GivenSteps(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, step int, length_fragment int, ) (ciphertext_out *rlwe.Ciphertext) {

	if step==0 {
		return ciphertext_in
	}

	var err error
	ciphertext_out, err = eval.RotateNew(ciphertext_in, length_fragment)
	if err != nil {
		panic(err)
	}
	for i:=1;i<step;i++ {
		ciphertext_out, err = eval.RotateNew(ciphertext_out, length_fragment)
		if err != nil {
			panic(err)
		}
	}
	return
}

func RotateRight_GivenSteps(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, step int, length_fragment int) (ciphertext_out *rlwe.Ciphertext) {
	
	if step==0 {
		return ciphertext_in
	}

	var err error
	ciphertext_out, err = eval.RotateNew(ciphertext_in, -length_fragment)
	if err != nil {
		panic(err)
	}
	for i:=1;i<step;i++ {
		ciphertext_out, err = eval.RotateNew(ciphertext_out, -length_fragment)
		if err != nil {
			panic(err)
		}
	}
	return
}

func RotateRight_OneSpot_GivenSteps_OnceDone(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, steps int) (ciphertext_out *rlwe.Ciphertext) {
	
	if steps==0 {
		return ciphertext_in
	}

	var err error
	ciphertext_out, err = eval.RotateNew(ciphertext_in, -steps)
	if err != nil {
		panic(err)
	}
	return
}