// 比 arragement2 多消耗一层level，并且需要更多的rotation，以及如果中心点个数比维数大的话会需要更多的密文条数。

package elaborate

import (
	"fmt"
	"goisbest/ciphertext/signcompare"
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
)

func ExtractPoints_1(params hefloat.Parameters, eval *hefloat.Evaluator, points_and_centers_ct *rlwe.Ciphertext, dimension int, num_points int) (points_ct *rlwe.Ciphertext) {
	
	points_ct = Mask_GetContinuousFragments(eval, points_and_centers_ct, 0, dimension, num_points)
	return
}

func ExtractCenters_1(params hefloat.Parameters, eval *hefloat.Evaluator, points_and_centers_ct *rlwe.Ciphertext, dimension int, num_points int, num_centers int) (centers_ct []*rlwe.Ciphertext) {

	centers_ct = make([]*rlwe.Ciphertext, num_centers)
	for i:=0;i<num_centers;i++ {
		center_ct := make([]*rlwe.Ciphertext, dimension)
		for j:=0;j<dimension;j++ {
			center_ct[j] = Mask_GetSingleFragment(eval, points_and_centers_ct, dimension*num_points + i+j*num_centers, 1)
			center_ct[j] = RotateLeft_GivenSteps(eval, center_ct[j], i, 1)
			center_ct[j] = RotateLeft_GivenSteps(eval, center_ct[j], j, num_centers)
			center_ct[j] = Rotate_GivenSteps(eval, center_ct[j], dimension - j, num_points)
		}
		centers_ct[i] = GetSum_CiphertextArray(eval, center_ct)
		centers_ct[i] = ExpandSpotsDownwards_Continuous_Fast(eval, centers_ct[i], num_points)
	}
	return centers_ct
}

func ComputeDistance_1(params hefloat.Parameters, eval *hefloat.Evaluator, points_ct *rlwe.Ciphertext, centers_ct []*rlwe.Ciphertext, dimension int, num_points int, num_centers int) (distances_ct []*rlwe.Ciphertext) {
	
	distances_ct = make([]*rlwe.Ciphertext, num_centers)

	var wg sync.WaitGroup
	for i:=0;i<num_centers;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			distances_ct[i], _ = eval.SubNew(points_ct, centers_ct[i])
			distances_ct[i], _ = eval.MulRelinNew(distances_ct[i], distances_ct[i])
			if err := eval.Rescale(distances_ct[i], distances_ct[i]); err != nil {  //rescale放在rot后面试试
				panic(err)
			}
	
			distance_rot_ct, err := eval.RotateNew(distances_ct[i], num_points)
			if err != nil {
				panic(err)
			}
			distances_ct[i], _ = eval.AddNew(distances_ct[i], distance_rot_ct)
			for j:=2;j<dimension;j++ {
				distance_rot_ct, err = eval.RotateNew(distance_rot_ct, num_points)
				if err != nil {
					panic(err)
				}
				distances_ct[i], err = eval.AddNew(distances_ct[i], distance_rot_ct)
				if err != nil {
					panic(err)
				}
			}
			distances_ct[i] = Mask_GetSingleFragment(eval, distances_ct[i], 0, num_points)

		}(i)
	}
	wg.Wait()
	return distances_ct
}

func CompareDistance_1(params hefloat.Parameters, eval *hefloat.Evaluator, distances_ct []*rlwe.Ciphertext, dimension int, num_points int, num_centers int, scale float64, eval_boot *bootstrapping.Evaluator) (bool_ct []*rlwe.Ciphertext) {
	
	var err error
	// 1 根据 map_MatrixToSequence 拼装 distances_ct 到一块
	map_SequenceToMatirx_up_rowprior, map_MatrixToSequence_up_rowprior_first, map_MatrixToSequence_up_rowprior_second := GetIndexMap_Up_RowPrior(num_centers)
	var sequence_distances_first_ct, sequence_distances_second_ct []*rlwe.Ciphertext
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		eval := eval.ShallowCopy()
		sequence_distances_first_ct = Assemble_SeparateFragments(eval, distances_ct, map_MatrixToSequence_up_rowprior_first, num_points)
	}()
	go func() {
		defer wg.Done()
		eval := eval.ShallowCopy()
		sequence_distances_second_ct = Assemble_SeparateFragments(eval, distances_ct, map_MatrixToSequence_up_rowprior_second, num_points)
	}()
	wg.Wait()

	// 2 进行比较操作，计算得到两条 sequence_arg
	quantity := len(sequence_distances_first_ct)
	sequence_arg_first_ct := make([]*rlwe.Ciphertext, quantity)
	sequence_arg_second_ct := make([]*rlwe.Ciphertext, quantity)
	for i:=0;i<quantity;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			eval_boot := eval_boot.ShallowCopy()
			sequence_arg_first_ct[i], sequence_arg_second_ct[i] = signcompare.CompareFunction(params, eval, sequence_distances_first_ct[i], sequence_distances_second_ct[i], eval_boot)
		}(i)
	}
	wg.Wait()
	fmt.Println("000000000000000000000000000000000")
	fmt.Println(len(sequence_arg_first_ct))
	fmt.Println("000000000000000000000000000000000")

	// 3 拆分两条 sequence_arg
	map_SequenceToMatirx_low_columnprior, _, _ := GetIndexMap_Low_ColumnPrior(num_centers)
	map_GroupBySecond_up_rowprior := GetIndexMap_SequenceToMatrix_GroupBySecond(map_SequenceToMatirx_up_rowprior)
	map_GroupBySecond_low_columnprior := GetIndexMap_SequenceToMatrix_GroupBySecond(map_SequenceToMatirx_low_columnprior)
	argMatrix_up_ct := make([]*rlwe.Ciphertext, num_centers-1)
	for key, value := range map_GroupBySecond_up_rowprior {
		wg.Add(1)
		go func(key int, value []Pair) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			argMatrix_up_ct[key-1] = Map_MultiIn_SingleOut(eval, sequence_arg_first_ct, value, num_points) // 要求预先确定输出可以一条密文装下
		}(key, value)
	}
	argMatrix_low_ct := make([]*rlwe.Ciphertext, num_centers-1)
	for key, value := range map_GroupBySecond_low_columnprior {
		wg.Add(1)
		go func(key int, value []Pair) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			argMatrix_low_ct[key] = Map_MultiIn_SingleOut(eval, sequence_arg_second_ct, value, num_points) // 要求预先确定输出可以一条密文装下
		}(key, value)
	}
	wg.Wait()
	
	// 4 拆分两条 sequence_arg 完毕，加和，得到 argMatrix_ct
	argMatrix_ct := make([]*rlwe.Ciphertext, num_centers-1)
	for i:=0;i<num_centers-1;i++ {
		argMatrix_ct[i], err = eval.AddNew(argMatrix_up_ct[i], argMatrix_low_ct[i])
		if err != nil {
			panic(err)
		}
	}

	// 5 连乘 argMatrix_ct，得到 bool_sequence_ct
	bool_sequence_ct := GetProduct_CiphertextArray(eval, argMatrix_ct)  // 在这里加bootstrap不管用，因为更新中心点的时候是要依赖于上一步的中心点的，所以必须得bootstrap中心点，不然level的消耗会随着迭代而传递下去
	bool_matrix_ct := make([]*rlwe.Ciphertext, num_centers)
	for i:=0;i<num_centers;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			eval := eval.ShallowCopy()
			locations_target := make([]int, dimension)
			for j:=0;j<dimension;j++ {
				locations_target[j] = j
			}
			bool_matrix_ct[i] = DuplicateFragments_FromSpecificLocation(eval, Mask_GetSingleFragment(eval, bool_sequence_ct, i, num_points), i, locations_target, num_points)
		}(i)
	}
	wg.Wait()
	return bool_matrix_ct
}

func UpdateAllCenters_1(params hefloat.Parameters, eval *hefloat.Evaluator, eval_InnerSum *hefloat.Evaluator, points_ct *rlwe.Ciphertext, bool_ct []*rlwe.Ciphertext, centers_ct []*rlwe.Ciphertext, dimension int, num_points int, num_centers int, eval_boot *bootstrapping.Evaluator) (newCenters_ct []*rlwe.Ciphertext) {
	
	var err error
	newCenters_ct = make([]*rlwe.Ciphertext, num_centers)
	var wg sync.WaitGroup
	for i:=0;i<num_centers;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			eval := eval.ShallowCopy()
			eval_InnerSum := eval_InnerSum.ShallowCopy()
			newCenters_ct[i] = UpdateSingleCenter_1(params, eval, eval_InnerSum, points_ct, bool_ct[i], centers_ct[i], num_points)
			newCenters_ct[i] = Mask_GetSpecificSpotInFragment_and_Rescale(eval, newCenters_ct[i], num_points, 0, dimension, num_points)//先缩放得到的更新中心点的值，反而更接近明文。可能是因为先缩放，导致bootstrap的时候slot里面的值相差不会太大，所以bootstrap的误差更小？
			newCenters_ct[i] = RotateRight_GivenSteps(eval, newCenters_ct[i], i, 1)	
		}(i)
	}
	wg.Wait()

	newCenters_AllCombinedInOne_ct := GetSum_CiphertextArray(eval, newCenters_ct)
	eval.SetScale(newCenters_AllCombinedInOne_ct, params.DefaultScale())  // 在bootstrap之前手动rescale？根据bootstrap的例子中说明是不用的
	newCenters_AllCombinedInOne_ct, err = eval_boot.Bootstrap(newCenters_AllCombinedInOne_ct)
	if err != nil {
		panic(err)
	}

	for i:=0;i<num_centers;i++ {
		wg.Add(1)
		go func(i int){
			defer wg.Done()
			eval := eval.ShallowCopy()
			newCenters_ct[i] = Mask_GetSpecificSpotInFragment_and_Rescale(eval, newCenters_AllCombinedInOne_ct, num_points, i, dimension, 1)
			newCenters_ct[i] = RotateLeft_GivenSteps(eval, newCenters_ct[i], i, 1)
			newCenters_ct[i] = ExpandSpotsDownwards_Continuous_Fast(eval, newCenters_ct[i], num_points)	
		}(i)
	}
	wg.Wait()
	return newCenters_ct
}

func UpdateSingleCenter_1(params hefloat.Parameters, eval *hefloat.Evaluator, eval_InnerSum *hefloat.Evaluator, points_ct *rlwe.Ciphertext, bool_ct *rlwe.Ciphertext, center_ct *rlwe.Ciphertext, num_points int) (newCenter_ct *rlwe.Ciphertext) {

	// points * bool + center*(1-bool) = points * bool + center - center * bool = (points - center) * bool + center
	var err error
	newCenter_ct, _ = eval.SubNew(points_ct, center_ct)
	newCenter_ct, _ = eval.MulRelinNew(newCenter_ct, bool_ct)
	if err = eval.Rescale(newCenter_ct, newCenter_ct); err != nil {
		panic(err)
	}
	newCenter_ct, _ = eval.AddNew(newCenter_ct, center_ct)

	if err := eval_InnerSum.InnerSum(newCenter_ct, 1, num_points, newCenter_ct); err != nil {
		panic(err)
	}
	return newCenter_ct
}