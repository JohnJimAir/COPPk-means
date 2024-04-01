package elaborate

import (
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func Assemble_SeparateFragments(eval *hefloat.Evaluator, ciphertexts_in []*rlwe.Ciphertext, map_assemble map[int][]int, length_fragment int) (ciphertexts_out []*rlwe.Ciphertext) {

	var keys []int
	for key := range map_assemble {
		keys = append(keys, key)
	}
	embedded := make([][]*rlwe.Ciphertext, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(i int, key int) {
			defer wg.Done()
			eval := eval.ShallowCopy()    //这里用并行肯定比串行快
			embedded[i] = DuplicateFragments_FromFirstLocation_MultiOut(eval, ciphertexts_in[key], map_assemble[key], length_fragment)
		}(i, key)
	}
	wg.Wait()
	return SumColumns(eval, embedded)
}

func Assemble_PiecedFragments( eval *hefloat.Evaluator, ciphertexts_in *rlwe.Ciphertext, map_assemble map[int][]int, length_fragment int) (ciphertexts_out []*rlwe.Ciphertext) {

	var keys []int
	for key := range map_assemble {
		keys = append(keys, key)
	}
	embedded := make([][]*rlwe.Ciphertext, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(i int, key int) {
			defer wg.Done()
			eval := eval.ShallowCopy()    //这里用并行肯定比串行快
			ciphertexts_in_fragmentpicked := Mask_GetSingleFragment(eval, ciphertexts_in, key, length_fragment)
			embedded[i] = DuplicateFragments_FromSpecificLocation_MultiOut(eval, ciphertexts_in_fragmentpicked, key, map_assemble[key], length_fragment)
		}(i, key)
	}
	wg.Wait()
	return SumColumns(eval, embedded)
}