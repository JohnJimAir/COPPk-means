package elaborate

import (
	"sort"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func EncryptPoints(params hefloat.Parameters, encoder *hefloat.Encoder, encryptor *rlwe.Encryptor, num_points int, dimension int, points [][]float64) (points_ct *rlwe.Ciphertext) {
	
	var err error
	points_values := make([]float64, params.MaxSlots())
	for i := 0; i < dimension; i++ {
		for j:=0;j<num_points;j++ {
			points_values[ num_points*i+j ] = points[i][j]
		}
	}

	points_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_values, points_pt); err != nil {
		panic(err)
	}
	if points_ct, err = encryptor.EncryptNew(points_pt); err != nil {
		panic(err)
	}
	return
}

func EncryptCenter(params hefloat.Parameters, encoder *hefloat.Encoder, encryptor *rlwe.Encryptor, num_points int, dimension int, center []float64, ) (center_ct *rlwe.Ciphertext) {
	
	var err error
	center_values := make([]float64, params.MaxSlots())
	for i := 0; i < dimension; i++ {
		for j:=0;j<num_points;j++ {
			center_values[ num_points*i+j ] = center[i]
		}
	}

	center_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(center_values, center_pt); err != nil {
		panic(err)
	}
	if center_ct, err = encryptor.EncryptNew(center_pt); err != nil {
		panic(err)
	}
	return
}

func AssembleForCompare_First_1_Seq(eval *hefloat.Evaluator, distances_ct []*rlwe.Ciphertext, map_MatrixToSequence_first map[int][]int, num_points int) (sequenceFirst_ct *rlwe.Ciphertext) {
	distances_ct = distances_ct[:len(distances_ct)-1] // first不需要最后一个中心点的distance_ct

	keys := make([]int, 0, len(map_MatrixToSequence_first))
	for key := range map_MatrixToSequence_first {
		keys = append(keys, key)
	}
	sort.Ints(keys)

	embedded := make([]*rlwe.Ciphertext, len(keys))
	for i:=0;i<len(keys);i++ {
		embedded[i] = DuplicateFragments_FromFirstLocation(eval, distances_ct[i], map_MatrixToSequence_first[keys[i]], num_points)//改造这个函数
	}
	return GetSum_CiphertextArray(eval, embedded)
}

func AssembleForCompare_Second_1_Seq(eval_Rotate *hefloat.Evaluator, distances_ct []*rlwe.Ciphertext, map_MatrixToSequence_second map[int][]int, num_points int) (sequenceSecond_ct *rlwe.Ciphertext) {
	distances_ct = distances_ct[1:]// second不需要distances0_ct

	keys := make([]int, 0, len(map_MatrixToSequence_second))
	for key := range map_MatrixToSequence_second {
		keys = append(keys, key)
	}
	sort.Ints(keys)

	embedded := make([]*rlwe.Ciphertext, len(keys))
	for i:=0;i<len(keys);i++ {
		embedded[i] = DuplicateFragments_FromFirstLocation(eval_Rotate, distances_ct[i], map_MatrixToSequence_second[keys[i]], num_points)
	}
	return GetSum_CiphertextArray(eval_Rotate, embedded)
}

func AssembleForCompare_First_2(eval *hefloat.Evaluator, distances_ct *rlwe.Ciphertext, Map_MatrixToSequence_first map[int][]int, num_points int) (sequenceFirst_ct *rlwe.Ciphertext) {

	keys := make([]int, 0, len(Map_MatrixToSequence_first))
	for key := range Map_MatrixToSequence_first {
		keys = append(keys, key)
	}
	sort.Ints(keys)

	embedded := make([]*rlwe.Ciphertext, len(keys))
	for i:=0;i<len(keys);i++ {
		distances_picked_ct := Mask_GetSingleFragment(eval, distances_ct, i, num_points)
		embedded[i] = DuplicateFragments_FromSpecificLocation(eval, distances_picked_ct, i, Map_MatrixToSequence_first[keys[i]], num_points)
	}
	return GetSum_CiphertextArray(eval, embedded)
}

func AssembleForCompare_Second_2(eval *hefloat.Evaluator, distances_ct *rlwe.Ciphertext, map_MatrixToSequence_second map[int][]int, num_points int) (sequenceFirst_ct *rlwe.Ciphertext) {

	keys := make([]int, 0, len(map_MatrixToSequence_second))
	for key := range map_MatrixToSequence_second {
		keys = append(keys, key)
	}
	sort.Ints(keys)

	embedded := make([]*rlwe.Ciphertext, len(keys))
	for i:=0;i<len(keys);i++ {
		distances_picked_ct := Mask_GetSingleFragment(eval, distances_ct, i+1, num_points)
		embedded[i] = DuplicateFragments_FromSpecificLocation(eval, distances_picked_ct, i+1, map_MatrixToSequence_second[keys[i]], num_points)
	}
	return GetSum_CiphertextArray(eval, embedded)
}

// 会被 utils_map 取代掉，使用 map 两次，分别作用于up、low
func SplitSequenceToMatrix_UpAndLow(params hefloat.Parameters, eval *hefloat.Evaluator, sequence_up *rlwe.Ciphertext, sequence_low *rlwe.Ciphertext, dim_matrix int, length_fragments int) (combinedFragments []*rlwe.Ciphertext) {
	
	var err error
	combinedFragments = make([]*rlwe.Ciphertext, dim_matrix-1)
	combinedFragments_up := SplitSequenceToMatrix_Up(params, eval, sequence_up, dim_matrix, length_fragments)
	combinedFragments_low := SplitSequenceToMatrix_Low(params, eval, sequence_low, dim_matrix, length_fragments)
	for i:=0;i<dim_matrix-1;i++ {
		combinedFragments[i], err = eval.AddNew(combinedFragments_up[i+1], combinedFragments_low[i])
		if err != nil {
			panic(err)
		}
	}
	return
}

// 变成更通用的函数，不针对矩阵的上三角，而是给map就行
func SplitSequenceToMatrix_Up(params hefloat.Parameters, eval *hefloat.Evaluator, sequence *rlwe.Ciphertext, dim_matrix int, length_fragments int) (combinedFragments []*rlwe.Ciphertext) {
	// 这个函数得整个改写，直接用 map 对应位置提取，所以不仔细设计rotate的细节来追求最大效率，而是用并行来加速。并且直接用 map 对应提取，也适用于中心点较多的情况。
	singleFragments := make([][]*rlwe.Ciphertext, dim_matrix)
	for i:=0;i<dim_matrix-1;i++ {
		singleFragments[i+1] = append(singleFragments[i+1], Mask_GetSingleFragment(eval, sequence, i, length_fragments))
		for j:=i+2;j<dim_matrix;j++ {
			sequence = RotateLeft_GivenSteps(eval, sequence, 1, length_fragments)  // sequence是通用的，并且rotation是有先后顺序的，没法并行
			singleFragments[j] = append(singleFragments[j], Mask_GetSingleFragment(eval, sequence, i, length_fragments))
		}
	}
	combinedFragments = make([]*rlwe.Ciphertext, dim_matrix)
	for i:=1;i<dim_matrix;i++ {
		combinedFragments[i] = GetSum_CiphertextArray(eval, singleFragments[i])
	}
	return combinedFragments
}

func SplitSequenceToMatrix_Low(params hefloat.Parameters, eval *hefloat.Evaluator, sequence *rlwe.Ciphertext, dim_matrix int, length_fragment int) (combinedFragments []*rlwe.Ciphertext) {
	// 这个同样要改写，为了简单直接地用 map 对应位置提取，放弃 Continuous 的提取方式。编写上会带来方便。同样不需要在原本的 sequence 上进行rotate。
	combinedFragments = make([]*rlwe.Ciphertext, dim_matrix)
	sequence = RotateRight_GivenSteps(eval, sequence, 1, length_fragment)
	combinedFragments[0] = Mask_GetContinuousFragments(eval, sequence, 1, dim_matrix-1, length_fragment)

	for i:=1;i<dim_matrix-1;i++ {
		sequence = RotateLeft_GivenSteps(eval, sequence, dim_matrix-1-i, length_fragment)
		combinedFragments[i] = Mask_GetContinuousFragments(eval, sequence, i+1, dim_matrix-1-i, length_fragment)
	}
	return combinedFragments
}