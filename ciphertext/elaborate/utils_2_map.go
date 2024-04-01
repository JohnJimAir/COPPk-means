package elaborate

import (
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

// 从disassemble改名为map

// duplicate, assemble, disassemble 都可以更抽象，变成广义上的 map。只不过 duplicate 预先就 mask 过了；assemble 则是 duplicate 的进阶版，根据是separate还是pieced，
// 来决定是否要 mask；而 disassemble 才是真正意义上的 map，其内部肯定需要预先mask，然后rotate。duplicate可以认为是map的特殊情形：只从一个片段到多个片段；而assemble则是默认
// 输入是一些小组件，输出由输入拼装而成，可以认为输出比输入“层次更高”、输入比输入“更大”；而disassemble则是从输入抽取一些片段(一个片段可以被选择多次)，然后再重新排列然后组合到一块，
// 所以输入和输出“层次是一样的”，谁也不比谁“更大”，而这正是map的意思。
// duplicate 当然也可以用map来实现，但是效率会变差。同样基于效率的考虑，assemble应该建立在duplicate之上，而不是map。
//

// []Pair
func Map_SingleIn_SingleOut(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, map_location []Pair, length_fragment int) (ciphertexts_out *rlwe.Ciphertext) {

	if len(map_location) == 0 {  // 返回 slot值全为0的密文
		ciphertext_out, err := eval.MulRelinNew(ciphertext_in, 0)
		if err != nil {
			panic(err)
		}
		return ciphertext_out
	}

	length := len(map_location)
	fragments_individual := make([]*rlwe.Ciphertext, length)
	// var wg sync.WaitGroup
	for i:=0;i<length;i++ {
		// wg.Add(1)
		// go func(i int) {
		// 	defer wg.Done()
		// 	eval := eval.ShallowCopy()
			fragments_individual[i] = Mask_GetSingleFragment(eval, ciphertext_in, map_location[i].First, length_fragment)
			fragments_individual[i] = Rotate_GivenSteps(eval, fragments_individual[i], map_location[i].First-map_location[i].Second, length_fragment)	
		// }(i)
	}
	// wg.Wait()
	ciphertexts_out = GetSum_CiphertextArray(eval, fragments_individual)
	return ciphertexts_out
}

// []Pair, 根据Pair所指定的map，输出可能无法由一条密文盛下。Pair.first 最大不能超过一条密文
// 从 single single 到 single multi 是简单直接的切片拼接
func Map_SingleIn_MultiOut(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, map_location []Pair, length_fragment int) (ciphertexts_out []*rlwe.Ciphertext) {
	// 这个函数没用到过，和下面的那个函数作用一样，都是用的下面的那个函数

	if len(map_location) == 0 { // 返回空的切片
		return ciphertexts_out
	}

	// 首先需要知道Pair.second的最大值，来确定需要几条密文，以此来确定给输出开辟多大的空间，并对 map_location 进行分割
	location_out_max := 0
	for i:=0;i<len(map_location);i++ {
		if location_out_max < map_location[i].Second {
			location_out_max = map_location[i].Second
		}
	}
	capacity, quantity := CalCapacityAndQuantity(ciphertext_in.Slots(), length_fragment, location_out_max+1)

	map_location_splited := make([][]Pair, quantity)
	for i:=0;i<len(map_location);i++ {
		index_group := map_location[i].Second / capacity
		map_location_splited[index_group] = append(map_location_splited[index_group], Pair{First: map_location[i].First, Second: map_location[i].Second % capacity})
	}

	ciphertexts_out = make([]*rlwe.Ciphertext, quantity)
	var wg sync.WaitGroup
	for i:=0;i<quantity;i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()    //这里用并行肯定比串行快
			ciphertexts_out[i] = Map_SingleIn_SingleOut(eval, ciphertext_in, map_location_splited[i], length_fragment)
		}(i)
	}
	wg.Wait()
	return ciphertexts_out
}

// []Pair，需要预先确定 Pair.second 最大也不会超过一条密文; 并且 Pair.first 不能超过 ciphertexts_in 的范围
// 从 single single 到  multi single 则是 GetSum_CiphertextArray
func Map_MultiIn_SingleOut(eval *hefloat.Evaluator, ciphertexts_in []*rlwe.Ciphertext, map_location []Pair, length_fragment int) (ciphertext_out *rlwe.Ciphertext) {

	if len(map_location) == 0 { // 返回空的切片
		return ciphertext_out
	}

	capacity, _ := CalCapacityAndQuantity(ciphertexts_in[0].Slots(), length_fragment, 1) // 只需要 capacity，所以最后一个参数随便填
	map_location_splited := make([][]Pair, len(ciphertexts_in))   // 有的位置可能是空的[]Pair切片
	for i:=0;i<len(map_location);i++ {
		index_group := map_location[i].First / capacity
		map_location_splited[index_group] = append(map_location_splited[index_group], Pair{First: map_location[i].First % capacity, Second: map_location[i].Second})
	}

	ciphertext_out_tmp := make([]*rlwe.Ciphertext, len(ciphertexts_in))
	var wg sync.WaitGroup
	for i:=0;i<len(map_location_splited);i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := eval.ShallowCopy()    //这里用并行肯定比串行快
			ciphertext_out_tmp[i] = Map_SingleIn_SingleOut(eval, ciphertexts_in[i], map_location_splited[i], length_fragment)
		}(i)
	}
	wg.Wait()
	ciphertext_out = GetSum_CiphertextArray(eval, ciphertext_out_tmp)
	return ciphertext_out
}


// []Pair， 支持更长的输入，但是在逻辑上输入是一整条密文。Pair.first 不能超过 ciphertexts_in 的范围
// 从 single multi 到 multi multi 得需要 sumcolumns
// 从 multi single 到 multi multi 则是简单直接的切片拼接
func Map_MultiIn_MultiOut(eval *hefloat.Evaluator, ciphertexts_in []*rlwe.Ciphertext, map_location []Pair, length_fragment int) (ciphertexts_out []*rlwe.Ciphertext) {
	// 只关于 Pair.first 进行分组，关于 Pair.second 的分组交给 SingleIn_MultiOut 处理, 但是最后要用 SumColumns 进行整合。

	capacity, _ := CalCapacityAndQuantity(ciphertexts_in[0].Slots(), length_fragment, 1) // 只需要 capacity，所以最后一个参数随便填
	map_location_splited := make([][]Pair, len(ciphertexts_in))
	for i:=0;i<len(map_location);i++ {
		index_group := map_location[i].First / capacity
		map_location_splited[index_group] = append(map_location_splited[index_group], Pair{First: map_location[i].First % capacity, Second: map_location[i].Second})
	}

	ciphertexts_out_tmp := make([][]*rlwe.Ciphertext, len(ciphertexts_in))
	for i:=0;i<len(map_location_splited);i++ {
		ciphertexts_out_tmp[i] = Map_SingleIn_MultiOut(eval, ciphertexts_in[i], map_location_splited[i], length_fragment)
	}
	ciphertexts_out = SumColumns(eval, ciphertexts_out_tmp)
	return ciphertexts_out
}