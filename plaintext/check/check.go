package check

func Transform_BoolMatrix_to_NumLabels(bool_matrix [][]float64) (labelSeq []int) {
	
	length_labelSeq := len(bool_matrix[0])
	labelSeq = make([]int, length_labelSeq)

	num_labels := len(bool_matrix)
	oneline := make([]float64, num_labels)
	for i:=0;i<length_labelSeq;i++ {
		for j:=0;j<num_labels;j++ {
			oneline[j] = bool_matrix[j][i]
		}
		labelSeq[i] = GetIndexofMaximum(oneline) + 1
	}
	return labelSeq
}

func CalculateCorrelation_AllPermutations(sequence_label_benchmark []int, sequence_label_tobetest []int, num_labels int) (ratio_correlation_max float64) {
	
	permutations := GetAllPermutations_GivenNumLabels(num_labels)
	num_permutations := len(permutations)

	ratio_correlation_max = 0
	for i:=0;i<num_permutations;i++ {
		sequence_label_permutationchanged := ChangePermutation(sequence_label_tobetest, permutations[i])
		if ratio_correlation_max < CalculateCorrelation(sequence_label_benchmark, sequence_label_permutationchanged) {
			ratio_correlation_max = CalculateCorrelation(sequence_label_benchmark, sequence_label_permutationchanged)
		}
	}
	return ratio_correlation_max
}