package elaborate

import (
	"fmt"
	"sync"
	"time"

	"goisbest/ciphertext/signcompare"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
)

func DuplicatePoints() () {}

func ExtractCentersFromEncryptedPoints_2() (){

}

func EncryptPoints_NoNeedExtract_2(params hefloat.Parameters, encoder *hefloat.Encoder, encryptor *rlwe.Encryptor, points [][]float64, dimension int, num_points int, num_centers int) (points_ct []*rlwe.Ciphertext) {
	
	// 不用把样本点的所有维度的数据一开始加密到一条密文中，而是直接就根据维度的数目来分配这么多条数目的密文，每条密文用到的slot数目是 num_points*num_centers
	// 所以当 dimension很大、dimension > num_centers 的时候，就可以直接调用这个接口。
	// 并且还省去了 rotate 和 duplicate 的过程
	var err error
	points_ct = make([]*rlwe.Ciphertext, dimension)

	for i:=0;i<dimension;i++ {
		points_values := make([]float64, params.MaxSlots())
		for j:=0;j<num_centers;j++ {
			for k:=0;k<num_points;k++ {  // 这里写法不好，循环写法太复杂了，应该直接条块复制
				points_values[ num_points*j+k ] = points[i][k]
			}
		}
		points_pt := hefloat.NewPlaintext(params, params.MaxLevel())
		if err = encoder.Encode(points_values, points_pt); err != nil {
			panic(err)
		}
		if points_ct[i], err = encryptor.EncryptNew(points_pt); err != nil {
			panic(err)
		}
	}
	return points_ct
}

// 道理和 EncryptPoints_NoNeedExtract_2 一样
// 省去了 rotate 和 expand 的过程
func EncryptCenters_NoNeedExtract_2(params hefloat.Parameters, encoder *hefloat.Encoder, encryptor *rlwe.Encryptor, centers [][]float64, dimension int, num_points int, num_centers int) (centers_ct []*rlwe.Ciphertext) {
	
	var err error
	centers_ct = make([]*rlwe.Ciphertext, dimension)

	for i:=0;i<dimension;i++ {
		center_values := make([]float64, params.MaxSlots())
		for j:=0;j<num_centers;j++ {
			for k:=0;k<num_points;k++ {  // 这里写法不好，循环写法太复杂了，应该直接条块复制
				center_values[ num_points*j+k ] = centers[i][j]
			}
		}
		center_pt := hefloat.NewPlaintext(params, params.MaxLevel())
		if err = encoder.Encode(center_values, center_pt); err != nil {
			panic(err)
		}
		if centers_ct[i], err = encryptor.EncryptNew(center_pt); err != nil {
			panic(err)
		}
	}
	return centers_ct
}

func ExtractPoints_2(params hefloat.Parameters, eval *hefloat.Evaluator, points_and_centers_ct *rlwe.Ciphertext, dimension int, num_points int, num_centers int) (points_ct []*rlwe.Ciphertext) {

	points_ct = make([]*rlwe.Ciphertext, dimension)
	for i:=0;i<dimension;i++ {
		points_ct[i] = Mask_GetSingleFragment(eval, points_and_centers_ct, i, num_points)

		locations_target := make([]int, num_centers)
		for j:=0;j<num_centers;j++ {
			locations_target[j] = j
		}
		points_ct[i] = DuplicateFragments_FromSpecificLocation(eval, points_ct[i], i, locations_target, num_points)
	}
	return points_ct
}

func ExtractCenters_2(params hefloat.Parameters, eval *hefloat.Evaluator, points_and_centers_ct *rlwe.Ciphertext, dimension int, num_points int, num_centers int) (centers_ct []*rlwe.Ciphertext) {

	centers_ct = make([]*rlwe.Ciphertext, dimension)
	for i:=0;i<dimension;i++ {
		centers_certainDimension_ct := make([]*rlwe.Ciphertext, num_centers)
		for j:=0;j<num_centers;j++ {
			centers_certainDimension_ct[j] = Mask_GetSingleFragment(eval, points_and_centers_ct, dimension*num_points + i*num_centers+j, 1)
			centers_certainDimension_ct[j] = RotateLeft_GivenSteps(eval, centers_certainDimension_ct[j], j, 1)
			centers_certainDimension_ct[j] = RotateLeft_GivenSteps(eval, centers_certainDimension_ct[j], i, num_centers)
			centers_certainDimension_ct[j] = Rotate_GivenSteps(eval, centers_certainDimension_ct[j], dimension - j, num_points)
		}
		centers_ct[i] = GetSum_CiphertextArray(eval, centers_certainDimension_ct)
		centers_ct[i] = ExpandSpotsDownwards_Continuous_Fast(eval, centers_ct[i], num_points)
	}
	return centers_ct
}

func ComputeDistance_2(eval *hefloat.Evaluator, points_ct []*rlwe.Ciphertext, centers_ct []*rlwe.Ciphertext, dimension int) (distances_ct *rlwe.Ciphertext) {
	
	slice := make([]*rlwe.Ciphertext, dimension)
	var wg sync.WaitGroup
	for i:=0;i<dimension;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			distances_certainDimension_ct, _ := eval.SubNew(points_ct[i], centers_ct[i])
			distances_certainDimension_ct, _ = eval.MulRelinNew(distances_certainDimension_ct, distances_certainDimension_ct)
			if err := eval.Rescale(distances_certainDimension_ct, distances_certainDimension_ct); err != nil {
				panic(err)
			}
			slice[i] = distances_certainDimension_ct
		}(i)
	}
	wg.Wait()
	return GetSum_CiphertextArray(eval, slice)
}

func CompareDistance_2(params hefloat.Parameters, eval *hefloat.Evaluator, distances_ct *rlwe.Ciphertext, dimension int, num_points int, num_centers int, eval_boot *bootstrapping.Evaluator) (bool_ct *rlwe.Ciphertext) {

	var err error
	// 1 根据 map_MatrixToSequence 来 assemble distances_ct ，注意这里是 PiecedFragments
	map_SequenceToMatirx_up_rowprior, map_MatrixToSequence_up_rowprior_first, map_MatrixToSequence_up_rowprior_second := GetIndexMap_Up_RowPrior(num_centers)
	var sequence_distances_first_ct, sequence_distances_second_ct []*rlwe.Ciphertext
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		eval := eval.ShallowCopy()
		sequence_distances_first_ct = Assemble_PiecedFragments(eval, distances_ct, map_MatrixToSequence_up_rowprior_first, num_points)
	}()
	go func() {
		defer wg.Done()
		eval := eval.ShallowCopy()
		sequence_distances_second_ct = Assemble_PiecedFragments(eval, distances_ct, map_MatrixToSequence_up_rowprior_second, num_points)
	}()
	wg.Wait()

	// 2 进行比较操作，计算得到两条 sequence_arg
	quantity := len(sequence_distances_first_ct)
	sequence_arg_first_ct := make([]*rlwe.Ciphertext, quantity)
	sequence_arg_second_ct := make([]*rlwe.Ciphertext, quantity)
	start_time := time.Now()
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
	end_time := time.Now()
	fmt.Printf("bootstrap 的时间: %s\n", end_time.Sub(start_time))

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
	return bool_sequence_ct
}

func UpdateAllCenters_2(params hefloat.Parameters, eval *hefloat.Evaluator, eval_InnerSum *hefloat.Evaluator, points_ct []*rlwe.Ciphertext, bool_ct *rlwe.Ciphertext, centers_ct []*rlwe.Ciphertext, dimension int, num_points int, num_centers int, eval_boot *bootstrapping.Evaluator) (newCenters_ct []*rlwe.Ciphertext) {

	var err error
	newCenters_ct = make([]*rlwe.Ciphertext, dimension)
	var wg sync.WaitGroup
	for i:=0;i<dimension;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			eval_InnerSum := eval_InnerSum.ShallowCopy()
			newCenters_ct[i] = UpdateSingleDimension_2(params, eval, eval_InnerSum, points_ct[i], bool_ct, centers_ct[i], num_points)
			newCenters_ct[i] = Mask_GetSpecificSpotInFragment_and_Rescale(eval, newCenters_ct[i], num_points, 0, num_centers, num_points)
			newCenters_ct[i] = RotateRight_GivenSteps(eval, newCenters_ct[i], i, 1)
		}(i)
	}
	wg.Wait()
	newCenters_allDimensionsCombined_ct := GetSum_CiphertextArray(eval, newCenters_ct)
	eval.SetScale(newCenters_allDimensionsCombined_ct, params.DefaultScale())  // 在bootstrap之前手动rescale？根据bootstrap的例子中说明是不用的
	start_time := time.Now() 
	newCenters_allDimensionsCombined_ct, err = eval_boot.Bootstrap(newCenters_allDimensionsCombined_ct)
	if err != nil {
		panic(err)
	}	
	end_time := time.Now()
	fmt.Printf("bootstrap 的时间: %s\n", end_time.Sub(start_time))
	if err != nil {
		panic(err)
	}
	
	for i:=0;i<dimension;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()
			newCenters_ct[i] = Mask_GetSpecificSpotInFragment_and_Rescale(eval, newCenters_allDimensionsCombined_ct, num_points, i, num_centers, 1)
			newCenters_ct[i] = RotateLeft_GivenSteps(eval, newCenters_ct[i], i, 1)
			newCenters_ct[i] = ExpandSpotsDownwards_Continuous_Fast(eval, newCenters_ct[i], num_points)
		}(i)
	}
	wg.Wait()

	return newCenters_ct
}

// 不像 rotate，innersum 的 eval 不能和普通的 eval 共用
func UpdateSingleDimension_2(params hefloat.Parameters, eval *hefloat.Evaluator, eval_InnerSum *hefloat.Evaluator, points_certainDimension_ct *rlwe.Ciphertext, bool_ct *rlwe.Ciphertext, centers_certainDimension_ct *rlwe.Ciphertext, num_points int) (newCenters_certainDimension_ct *rlwe.Ciphertext) {

	// points * bool + center*(1-bool) = points * bool + center - center * bool = (points - center) * bool + center
	var err error
	newCenters_certainDimension_ct, _ = eval.SubNew(points_certainDimension_ct, centers_certainDimension_ct)
	newCenters_certainDimension_ct, _ = eval.MulRelinNew(newCenters_certainDimension_ct, bool_ct)
	if err = eval.Rescale(newCenters_certainDimension_ct, newCenters_certainDimension_ct); err != nil {
		panic(err)
	}
	newCenters_certainDimension_ct, _ = eval.AddNew(newCenters_certainDimension_ct, centers_certainDimension_ct)
	if err := eval_InnerSum.InnerSum(newCenters_certainDimension_ct, 1, num_points, newCenters_certainDimension_ct); err != nil {
		panic(err)
	}
	return newCenters_certainDimension_ct
}