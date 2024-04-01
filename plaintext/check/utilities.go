package check

func GetIndexofMaximum(oneline []float64) (index_max int) {
	
	max := oneline[0]
	index_max = 0
	for i:=1;i<len(oneline);i++ {
		if oneline[i] > max {
			max = oneline[i]
			index_max = i
		}
	}
	return index_max
}

func GetAllPermutations_GivenNumLabels(num_labels int) (permutations [][]int) {
	
	sequence_start := make([]int, num_labels)
	for i:=0;i<num_labels;i++ {
		sequence_start[i] = i+1
	}

	used := make([]int, num_labels)

	return CalculateAllPermutations(sequence_start, used, num_labels, num_labels)
}

func CalculateAllPermutations(sequence []int, used []int, num_remained int, length_sequnence int) (permutations [][]int) {

	if num_remained == 2 {
		permutation_1 := make([]int, 2)
		count := 0
		for i:=0;i<length_sequnence;i++ {
			if used[i] == 0 {
				permutation_1[count] = sequence[i]
				count++
			}
		}

		permutation_2 := make([]int, 2)
		permutation_2[1] = permutation_1[0]
		permutation_2[0] = permutation_1[1]

		permutations = make([][]int, 2)
		permutations[0] = permutation_1
		permutations[1] = permutation_2
		return permutations
	}

	index_wherezero := GetIndex_WhereZero(used)
	for i:=0;i<len(index_wherezero);i++ {
		used[index_wherezero[i]] = 1
		num_remained --
		permutations_thistime := PutTogether(sequence[index_wherezero[i]], CalculateAllPermutations(sequence, used, num_remained, length_sequnence))
		permutations = append(permutations, permutations_thistime...)

		used[index_wherezero[i]] = 0
		num_remained ++
	}
	return permutations
}

func PutTogether(element int, sequences_in [][]int) (sequences_out [][]int) {
	
	sequences_out = make([][]int, len(sequences_in))
	for i:=0;i<len(sequences_in);i++ {
		sequences_out[i] = append([]int{element}, sequences_in[i]...)
	}
	return sequences_out
}

func GetIndex_WhereZero(sequence_bool []int) (index_wherezero []int) {
	
	for i:=0;i<len(sequence_bool);i++ {
		if sequence_bool[i]==0 {
			index_wherezero = append(index_wherezero, i)
		}
	}
	return index_wherezero
}

// sequence_label_in[i] 不能超过permutaion的最大下标
func ChangePermutation(sequence_label_in []int, permutation []int) (sequence_label_out []int) {
	
	length := len(sequence_label_in)
	sequence_label_out = make([]int, length)
	for i:=0;i<length;i++ {
		sequence_label_out[i] = permutation[sequence_label_in[i]-1]
	}
	return sequence_label_out
}

// 进入接口之前注意两个序列的长度得一样
func CalculateCorrelation(sequence_label_1 []int, sequence_label_2 []int) (ratio_correlation float64) {
	
	length := len(sequence_label_1)
	count_same := 0
	for i:=0;i<length;i++ {
		if sequence_label_1[i] == sequence_label_2[i] {
			count_same++
		}
	}
	ratio_correlation = float64(count_same) / float64(length)
	return ratio_correlation
}