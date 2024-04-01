package elaborate

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

type Pair struct {
    First  int
    Second int
}

func GetPowerof2_Smaller(num int) (powerof2 int) {

	power := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
	for i:=0;i<len(power);i++ {
		if num <= power[i] {return power[i-1]}
	}
	return 
}

func GetPowerof2_SmallerOrEqual(num int) (powerof2 int) {

	power := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
	for i:=0;i<len(power);i++ {
		if num < power[i] {return power[i-1]}
	}
	return
}

func GetPowerof2_Bigger(num int) (powerof2 int) {

	power := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
	for i:=0;i<len(power);i++ {
		if num < power[i] {return power[i]}
	}
	return 
}

func GetIndexMap_Up_RowPrior(dimension int) (map[int]Pair, map[int][]int, map[int][]int) {
	
	map_SequenceToMatirx := make(map[int]Pair)
	index_sequence := 0
	for i:=0;i<dimension-1;i++ {
		for j:=i+1;j<dimension;j++ {
			map_SequenceToMatirx[index_sequence] = Pair{i, j}
			index_sequence++
		}
	}

	map_MatrixToSequence_first := make(map[int][]int)
	map_MatrixToSequence_second := make(map[int][]int)
	for key, value := range map_SequenceToMatirx {
		map_MatrixToSequence_first[value.First] = append(map_MatrixToSequence_first[value.First], key)
		map_MatrixToSequence_second[value.Second] = append(map_MatrixToSequence_second[value.Second], key)
	}
	return map_SequenceToMatirx, map_MatrixToSequence_first, map_MatrixToSequence_second
}

func GetIndexMap_Low_ColumnPrior(dimension int) (map[int]Pair, map[int][]int, map[int][]int) {
	
	map_SequenceToMatirx := make(map[int]Pair)
	index_sequence := 0
	for i:=0;i<dimension-1;i++ {
		for j:=i+1;j<dimension;j++ {
			map_SequenceToMatirx[index_sequence] = Pair{j, i}
			index_sequence++
		}
	}

	map_MatrixToSequence_first := make(map[int][]int)
	map_MatrixToSequence_second := make(map[int][]int)
	for key, value := range map_SequenceToMatirx {
		map_MatrixToSequence_first[value.First] = append(map_MatrixToSequence_first[value.First], key)
		map_MatrixToSequence_second[value.Second] = append(map_MatrixToSequence_second[value.Second], key)
	}
	return map_SequenceToMatirx, map_MatrixToSequence_first, map_MatrixToSequence_second
}

// 应该要求 map_SequenceToMatirx 中的所有 key 是唯一的，所有的 value 也是唯一的。象征sequence和matrix上的点位是一一映射。
// 而不存在matrix上的两个点位映射到sequence 的同一个点位上（value不唯一），这样的话再反映射回去就会导致 matrix上的两个点位的值是它们之前的值的加和。
// 也不应该有 sequence 上的两个点位映射到matrix的同一个点位上，这样的话反映射回去就会导致 matrix 上的点位是sequence上的两个点位的加和。
func GetIndexMap_SequenceToMatrix_GroupBySecond(map_SequenceToMatirx map[int]Pair) (map_GroupBySecond map[int][]Pair) {
	
	map_GroupBySecond = make(map[int][]Pair)
	for key, value := range map_SequenceToMatirx {
		map_GroupBySecond[value.Second] = append(map_GroupBySecond[value.Second], Pair{First: key, Second: value.First})
	}
	return map_GroupBySecond
}

func GetSum_CiphertextArray(eval *hefloat.Evaluator, ciphertexts []*rlwe.Ciphertext) (sum_ct *rlwe.Ciphertext) {
	
	var err error
	sum_ct = ciphertexts[0]
	for i:=1;i<len(ciphertexts);i++ {
		sum_ct, err = eval.AddNew(sum_ct, ciphertexts[i])
		if err != nil {
			panic(err)
		}
	}
	return
}

func GetProduct_CiphertextArray(eval *hefloat.Evaluator, ciphertexts []*rlwe.Ciphertext) (product_ct *rlwe.Ciphertext) {
	
	var err error
	length := len(ciphertexts)
	for length >= 2 {  // 没考虑bootstrap，length不能太大
		for i:=0;i<length/2;i++ {
			ciphertexts[i], err = eval.MulRelinNew(ciphertexts[2*i], ciphertexts[2*i+1])
			if err != nil {
				panic(err)
			}
			if err = eval.Rescale(ciphertexts[i], ciphertexts[i]); err != nil {
				panic(err)
			}
		}
		if length%2 != 0 {
			ciphertexts[length/2] = ciphertexts[length-1]
			length = length/2 + 1
		} else {
			length = length/2
		}
	}
	return ciphertexts[0]
}

func SumColumns(eval *hefloat.Evaluator, ciphertexts_in [][]*rlwe.Ciphertext) (ciphertexts_out []*rlwe.Ciphertext) {

	num_row := len(ciphertexts_in)
	num_col := 0
	for i:=0;i<num_row;i++ {
		if num_col < len(ciphertexts_in[i]) {
			num_col = len(ciphertexts_in[i])
		}
	}

	ciphertexts_out = make([]*rlwe.Ciphertext, num_col)
	for i:=0;i<num_col;i++ {
		var ciphertext_onecolumn []*rlwe.Ciphertext
		for j:=0;j<num_row;j++ {
			if i<len(ciphertexts_in[j]) {
				ciphertext_onecolumn = append(ciphertext_onecolumn, ciphertexts_in[j][i])
			}
		}
		ciphertexts_out[i] = GetSum_CiphertextArray(eval, ciphertext_onecolumn)
	}
	return ciphertexts_out
}

// 特别注意最后一个输入参数 num_elements 和 location 之间的关系，等于最大的 location+1
func CalCapacityAndQuantity(volume_container int, size_element int, num_elements int) (capacity int, quantity int) {
	capacity = volume_container / size_element
	if num_elements % capacity == 0 {
		quantity = num_elements / capacity
	} else { 
		quantity = num_elements / capacity + 1
	}
	return capacity, quantity
}

func SplitLocationSlice_AccordingCapacity(locations []int, capacity int) (locations_splited [][]int) {
	
	_, quantity := CalCapacityAndQuantity(capacity, 1, locations[len(locations)-1]+1)
	locations_splited = make([][]int, quantity)
	for i:=0;i<len(locations);i++ {
		index_group := locations[i] / capacity
		value_changed := locations[i] % capacity
		locations_splited[index_group] = append(locations_splited[index_group], value_changed)
	}
	return locations_splited
}