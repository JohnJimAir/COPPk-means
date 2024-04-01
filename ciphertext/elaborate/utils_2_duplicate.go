package elaborate

import (
	"sort"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

// 一个或多个输出，返回参数是切片的形式
func DuplicateFragments_FromFirstLocation_MultiOut(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, locations_target []int, length_fragment int) (ciphertext_out []*rlwe.Ciphertext) {
	// 首先对 locations_target 进行预先判断，决定怎么分割对应到不同的结果密文上，然后对于不同的结果密文，应该是可以并行的。
	sort.Ints(locations_target)
	capacity, quantity := CalCapacityAndQuantity( ciphertext_in.Slots(), length_fragment, locations_target[len(locations_target)-1]+1 )
	locations_target_splited := SplitLocationSlice_AccordingCapacity(locations_target, capacity)
	
	ciphertext_out = make([]*rlwe.Ciphertext, quantity)
	// var wg sync.WaitGroup
	for i:=0;i<quantity;i++ {
		// wg.Add(1)
		// go func(i int) {
		// 	defer wg.Done()
		// 	eval := eval.ShallowCopy()
			ciphertext_out[i] = DuplicateFragments_FromFirstLocation(eval, ciphertext_in, locations_target_splited[i], length_fragment)
		// }(i)
	}
	// wg.Wait()
	return ciphertext_out
}

func DuplicateFragments_FromFirstLocation(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, locations_target []int, length_fragment int) (ciphertext_out *rlwe.Ciphertext) {
	
	if len(locations_target) == 0 {
		ciphertext_out, err := eval.MulRelinNew(ciphertext_in, 0)
		if err != nil {
			panic(err)
		}
		return ciphertext_out
	}

	sort.Ints(locations_target)
	var slice []*rlwe.Ciphertext
	step := locations_target[0]
	slice = append(slice, RotateRight_GivenSteps(eval, ciphertext_in, step, length_fragment))
	for i:=1;i<len(locations_target);i++ {
		step = locations_target[i] - locations_target[i-1]
		slice = append(slice, RotateRight_GivenSteps(eval, slice[i-1], step, length_fragment))
	}

	ciphertext_out = GetSum_CiphertextArray(eval, slice)
	return ciphertext_out
}

func DuplicateFragments_FromSpecificLocation_MultiOut(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location_specific int, locations_target []int, length_fragment int) (ciphertext_out []*rlwe.Ciphertext){
	
	sort.Ints(locations_target)
	capacity, quantity := CalCapacityAndQuantity( ciphertext_in.Slots(), length_fragment, locations_target[len(locations_target)-1]+1 )
	locations_target_splited := SplitLocationSlice_AccordingCapacity(locations_target, capacity)
	
	ciphertext_out = make([]*rlwe.Ciphertext, quantity)
	// var wg sync.WaitGroup
	for i:=0;i<quantity;i++ {
		// wg.Add(1)
		// go func(i int) {
		// 	defer wg.Done()
		// 	eval := eval.ShallowCopy()
			ciphertext_out[i] = DuplicateFragments_FromSpecificLocation(eval, ciphertext_in, location_specific, locations_target_splited[i], length_fragment)
		// }(i)
	}
	// wg.Wait()
	return ciphertext_out
}

func DuplicateFragments_FromSpecificLocation(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location_specific int, locations_target []int, length_fragment int) (ciphertext_out *rlwe.Ciphertext){

	if len(locations_target) == 0 {
		ciphertext_out, err := eval.MulRelinNew(ciphertext_in, 0)
		if err != nil {
			panic(err)
		}
		return ciphertext_out
	}

	var err error
	sort.Ints(locations_target)
	index := sort.Search(len(locations_target), func(i int) bool {
		return locations_target[i] >= location_specific
	})
	if index == 0 {
		return DuplicateFragments_FromSpecificLocation_Right(eval, ciphertext_in, location_specific, locations_target, length_fragment)
	} else if index == len(locations_target) {	
		return DuplicateFragments_FromSpecificLocation_Left(eval, ciphertext_in, location_specific, locations_target, length_fragment)
	} else {
		left := DuplicateFragments_FromSpecificLocation_Left(eval, ciphertext_in, location_specific, locations_target[:index], length_fragment)
		right := DuplicateFragments_FromSpecificLocation_Right(eval, ciphertext_in, location_specific, locations_target[index:], length_fragment)
		ciphertext_out, err = eval.AddNew(left, right)
		if err != nil {
			panic(err)
		}
		return ciphertext_out
	}
}

func DuplicateFragments_FromSpecificLocation_Left(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location_specific int, locations_target []int, length_fragment int) (ciphertext_out *rlwe.Ciphertext){
	
	sort.Ints(locations_target)
	stepArray := make([]int, len(locations_target))
	for i:=0;i<len(locations_target);i++ {
		stepArray[i] = location_specific - locations_target[len(locations_target)-1 - i]
	}

	var slice []*rlwe.Ciphertext
	step := stepArray[0]
	slice = append(slice, RotateLeft_GivenSteps(eval, ciphertext_in, step, length_fragment))
	for i:=1;i<len(stepArray);i++ {
		step = stepArray[i] - stepArray[i-1]   // 强耦合，但是改为并行应该也节省不了时间，因为并行中最大的旋转次数也是这里串行的最大旋转次数
		slice = append(slice, RotateLeft_GivenSteps(eval, slice[i-1], step, length_fragment))  // 串行多了append操作，并行需要预先开辟好数组空间，并且并行本身也会有额外的开销，所以这里并行和串行应该差不多
	}

	ciphertext_out = GetSum_CiphertextArray(eval, slice)
	return
}

func DuplicateFragments_FromSpecificLocation_Right(eval *hefloat.Evaluator, ciphertext_in *rlwe.Ciphertext, location_specific int, locations_target []int, length_fragment int) (ciphertext_out *rlwe.Ciphertext){
	
	sort.Ints(locations_target)
	stepArray := make([]int, len(locations_target))
	for i:=0;i<len(locations_target);i++ {
		stepArray[i] = locations_target[i] - location_specific
	}

	var slice []*rlwe.Ciphertext
	step := stepArray[0]
	slice = append(slice, RotateRight_GivenSteps(eval, ciphertext_in, step, length_fragment))
	for i:=1;i<len(stepArray);i++ {
		step = stepArray[i] - stepArray[i-1]
		slice = append(slice, RotateRight_GivenSteps(eval, slice[i-1], step, length_fragment))
	}

	ciphertext_out = GetSum_CiphertextArray(eval, slice)
	return
}