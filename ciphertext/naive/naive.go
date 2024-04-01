package naive

import (
	"goisbest/ciphertext/signcompare"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
)

func ComputeDistance_OnePoint(eval *hefloat.Evaluator, dimension int, points_ct []*rlwe.Ciphertext, center_ct []*rlwe.Ciphertext) (distances_point_ct *rlwe.Ciphertext) {
	var err error
	distances_point_ct = ComputeDistance_OneDim(eval, points_ct[0], center_ct[0])

	for i:=1;i<dimension;i++ {
		distances_dim_ct := ComputeDistance_OneDim(eval, points_ct[i], center_ct[i])
		distances_point_ct, err = eval.AddNew(distances_point_ct, distances_dim_ct)
		if err != nil {
			panic(err)
		}
	}
	return 
}

func ComputeDistance_OneDim(eval *hefloat.Evaluator, points_ct *rlwe.Ciphertext, center_ct *rlwe.Ciphertext) (distances_ct *rlwe.Ciphertext) {

	distances_ct, _ = eval.SubNew(points_ct, center_ct)
	distances_ct, _ = eval.MulRelinNew(distances_ct, distances_ct)
	if err := eval.Rescale(distances_ct, distances_ct); err != nil {
		panic(err)
	}
	return
}

func CompareFunction_matrix(params hefloat.Parameters, eval *hefloat.Evaluator, num_centers int, distanceMatrix_ct []*rlwe.Ciphertext, eval_boot *bootstrapping.Evaluator) (boolMatrix_ct []*rlwe.Ciphertext) {

	bool0_ct, bool1_ct := signcompare.CompareFunction(params, eval, distanceMatrix_ct[0], distanceMatrix_ct[1], eval_boot)
	boolMatrix_ct = append(boolMatrix_ct, bool0_ct)
	boolMatrix_ct = append(boolMatrix_ct, bool1_ct)
	newdis_ct := GetNewDistance(eval, bool0_ct, distanceMatrix_ct[0], bool1_ct, distanceMatrix_ct[1])

	for i:=1;i<(num_centers-1);i++ {
		bool0_ct, bool1_ct = signcompare.CompareFunction(params, eval, newdis_ct, distanceMatrix_ct[i+1], eval_boot)
		UpdateBoolMatrix(eval, boolMatrix_ct, bool0_ct)
		boolMatrix_ct = append(boolMatrix_ct, bool1_ct)
		newdis_ct = GetNewDistance(eval, bool0_ct, newdis_ct, bool1_ct, distanceMatrix_ct[i+1])
	}
	return
}

func GetNewDistance(eval *hefloat.Evaluator, bool0_ct *rlwe.Ciphertext, dis0_ct *rlwe.Ciphertext, bool1_ct *rlwe.Ciphertext, dis1_ct *rlwe.Ciphertext) (newdis_ct *rlwe.Ciphertext) {

	//可能得先检查一下scale和level，
	newdis0_ct, err := eval.MulRelinNew(bool0_ct, dis0_ct)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(newdis0_ct, newdis0_ct); err != nil {
		panic(err)
	}
	newdis1_ct, err := eval.MulRelinNew(bool1_ct, dis1_ct)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(newdis1_ct, newdis1_ct); err != nil {
		panic(err)
	}
	//可能得先检查一下scale和level，然后才能相加
	newdis_ct, err = eval.AddNew(newdis0_ct, newdis1_ct)
	if err != nil {
		panic(err)
	}
	return
}

func UpdateBoolMatrix(eval *hefloat.Evaluator, boolMatrix_ct []*rlwe.Ciphertext, bool0_ct *rlwe.Ciphertext) () {
	var err error
	for i := range boolMatrix_ct {
		boolMatrix_ct[i], err = eval.MulRelinNew(boolMatrix_ct[i], bool0_ct)
		if err != nil {
			panic(err)
		}
		if err = eval.Rescale(boolMatrix_ct[i], boolMatrix_ct[i]); err != nil {
			panic(err)
		}
	}
}

func UpdateCenter_OnePoint(params hefloat.Parameters, eval *hefloat.Evaluator, number int, dimension int, points_ct []*rlwe.Ciphertext, center_ct []*rlwe.Ciphertext, bool_ct *rlwe.Ciphertext, eval_InnerSum *hefloat.Evaluator, batch int, n int) (newCenter_ct []*rlwe.Ciphertext) {

	for i:=0;i<dimension;i++ {
		newCenter_dim_ct := UpdateCenter_OneDim(params, eval, number, points_ct[i], center_ct[i], bool_ct, eval_InnerSum, batch, n)
		newCenter_ct = append(newCenter_ct, newCenter_dim_ct)
	}
	return
}

func UpdateCenter_OneDim(params hefloat.Parameters, eval *hefloat.Evaluator, num_points int, points_ct *rlwe.Ciphertext, center_ct *rlwe.Ciphertext, bool_ct *rlwe.Ciphertext, eval_InnerSum *hefloat.Evaluator, batch int, n int) (newCenter_ct *rlwe.Ciphertext) {

	// points * bool + center*(1-bool) = points * bool + center - center * bool = (points - center) * bool + center
	newCenter_ct, _ = eval.SubNew(points_ct, center_ct)
	newCenter_ct, _ = eval.MulRelinNew(newCenter_ct, bool_ct)
	if err := eval.Rescale(newCenter_ct, newCenter_ct); err != nil {
		panic(err)
	}
	newCenter_ct, _ = eval.AddNew(newCenter_ct, center_ct)

	// create mask
	mask_values := make([]float64, params.MaxSlots())
	for i := range mask_values {
		mask_values[i] = 0.0
	}
	for i := 0; i < num_points; i++ {
		mask_values[i] = 1.0
	}

	// multiply with mask
	newCenter_ct, err := eval.MulRelinNew(newCenter_ct, mask_values)
	if err != nil {
		panic(err)
	}
	if err = eval.Rescale(newCenter_ct, newCenter_ct); err != nil {
		panic(err)
	}

	// innersum
	newCenter_ct, err = eval.MulRelinNew(newCenter_ct, 1.0/float64(num_points))
	if err != nil {
		panic(err)
	}
	if err := eval_InnerSum.InnerSum(newCenter_ct, batch, n, newCenter_ct); err != nil {
		panic(err)
	}
	// rescale过后会有小误差，rescale放在InnerSum之前也会有小误差，很奇怪
	if err = eval.Rescale(newCenter_ct, newCenter_ct); err != nil {
		panic(err)
	}

	return
}