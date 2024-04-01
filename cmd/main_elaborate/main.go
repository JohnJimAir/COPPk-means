package main

import (
	"flag"
	"fmt"
	"goisbest/ciphertext/elaborate"
	"goisbest/plaintext"
	"goisbest/plaintext/check"
	"goisbest/utilities"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

var flagShort = flag.Bool("short", false, "run the example with a smaller and insecure ring degree.")

func main() {

	// file_directory := "/home/chenjingwei/z_dataset"
	// num_points := 256
	// dimension := 16
	// interval_start, interval_end := -1.0, 1.0
	// num_centers := 2
	// points, centers, scale := utilities.ReadPEGASUS(file_directory, num_points, dimension, interval_start, interval_end, num_centers)


	filepath := "/home/chenjingwei/z_dataset/Lsun.csv"
	points, dimension, num_points, num_centers, scale, labelSeq_benchmark := utilities.ReadFCPS(filepath)
	points = utilities.Rescale(points, scale)

	flag.Parse()
	LogN := 16
	if *flagShort {
		LogN -= 3
	}

	startTime := time.Now()
	var params hefloat.Parameters
	var err error
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            LogN,                                              // Log2 of the ring degree
			LogQ:            []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}, // Log2 of the ciphertext prime moduli
			LogP:            []int{61, 61, 61},                                 // Log2 of the key-switch auxiliary prime moduli
			LogDefaultScale: 40,                                                // Log2 of the scale
			Xs:              ring.Ternary{H: 192},
			RingType:        0,
		}); err != nil {
		panic(err)
	}
	// if params, err = hefloat.NewParametersFromLiteral(examples.HEFloatComplexParams[4]); err != nil {
	// 	panic(err)
	// }
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	encoder := hefloat.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)
	eval := hefloat.NewEvaluator(params, evk)

	// LogSlots := params.LogMaxSlots()
	// Slots := 1 << LogSlots


	fmt.Println("== GENERATE ROTATION EVALUATOR ==")
	galEls := []uint64{
		params.GaloisElement(num_points), params.GaloisElement(-num_points), params.GaloisElement(1), params.GaloisElement(-1), params.GaloisElement(num_centers),
	}
	for i := elaborate.GetPowerof2_SmallerOrEqual(num_points);i>=2;i/=2 {
		galEls = append(galEls, params.GaloisElement(-i))
	}
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...))
	// rotate这里可以直接写成eval，不会影响原来的作用，之后需要统一修改func的输入参数。对于下面的eval_Innersum则不是这样。


	fmt.Println("== GENERATE BOOTSTRAP EVALUATOR ==")
	btpParametersLit := bootstrapping.ParametersLiteral{
		LogN: utils.Pointy(LogN),
	}
	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}
	fmt.Println("Generating bootstrapping evaluation keys...")
	evk_boot, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")
	var eval_boot *bootstrapping.Evaluator
	if eval_boot, err = bootstrapping.NewEvaluator(btpParams, evk_boot); err != nil {
		panic(err)
	}

	fmt.Println("== GENERATE INNRESUM EVALUATOR ==")
	batch := 1
	n := num_points
	eval_Innersum := eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batch, n), sk)...))
	endTime := time.Now()
	fmt.Printf("生成时间: %s\n", endTime.Sub(startTime))


	// fmt.Println("== ENCRYPT PROVIDED VALUES ALLINONE ==")
	// points_and_centers_ct := slotexpansion.EncryptPointsAndCenters_AllInOne(params, encoder, encryptor, points, centers, dimension, num_points, num_centers)


// 	fmt.Printf("======================================================= arrangement1 =======================================================\n")
// 	fmt.Printf("== EXTRACT POINTS AND CENTERS ==\n")
// 	points_ct_1 := slotexpansion.ExtractPoints_1(params, eval, points_and_centers_ct, dimension, num_points)
// 	centers_ct_1 := slotexpansion.ExtractCenters_1(params, eval, points_and_centers_ct, dimension, num_points, num_centers)

// startTime = time.Now()
// for k:=0;k<3;k++ {
// fmt.Printf("=============================== 当前是第 %d 次循环 ===============================\n", k)

// 	fmt.Printf("== COMPUTE DISTANCE ==\n")
// 	distances_ct_1 := slotexpansion.ComputeDistance_1(params, eval, points_ct_1, centers_ct_1, dimension, num_points, num_centers)

// 	fmt.Printf("== DISTANCE COMPARISON ==\n")
// 	bool_ct_1 := slotexpansion.CompareDistance_1(params, eval, distances_ct_1, dimension, num_points, num_centers, scale, eval_boot)

// 	fmt.Printf("== UPDATE CENTERS ==\n")
// 	centers_ct_1 = slotexpansion.UpdateAllCenters_1(params, eval, eval_Innersum, points_ct_1, bool_ct_1, centers_ct_1, dimension, num_points, num_centers, eval_boot)
// 	for i:=0;i<num_centers;i++ {
// 		myfunctions.PrintPlaintext_Long(params, centers_ct_1[i], encoder, decryptor, 8, 2, 2)
// 	}
// }
// endTime = time.Now()
// fmt.Printf("程序执行时间: %s\n", endTime.Sub(startTime))



	fmt.Printf("======================================================= arrangement2 =======================================================\n")
	fmt.Printf("== EXTRACT POINTS AND CENTERS ==\n")
	index_centers := make([]int, num_centers)
	for i := 0; i < num_centers; i++ {
		index_centers[i] = i
	}
	centers := plaintext.ExtractCentersFromPoints(points, index_centers)
	// Implement extract later, first resolve scale.

	// points_ct_2 := slotexpansion.ExtractPoints_2(params, eval, points_and_centers_ct, dimension, num_points, num_centers)
	// centers_ct_2 := slotexpansion.ExtractCenters_2(params, eval, points_and_centers_ct, dimension, num_points, num_centers)
	points_ct_2  := elaborate.EncryptPoints_NoNeedExtract_2(params, encoder, encryptor, points, dimension, num_points, num_centers)
	centers_ct_2 := elaborate.EncryptCenters_NoNeedExtract_2(params, encoder, encryptor, centers, dimension, num_points, num_centers)
	
	var bool_ct_2 *rlwe.Ciphertext

	start_time2 := time.Now()
	times_updateCenters := 2
	for k := 1; k <= times_updateCenters+1; k++ {
		fmt.Printf("=============================== 当前是第 %d 次循环 ===============================\n", k)

		fmt.Printf("== COMPUTE DISTANCE ==\n")
		distances_ct_2 := elaborate.ComputeDistance_2(eval, points_ct_2, centers_ct_2, dimension)

		fmt.Printf("== DISTANCE COMPARISON ==\n")
		bool_ct_2 = elaborate.CompareDistance_2(params, eval, distances_ct_2, dimension, num_points, num_centers, eval_boot)

		// if k == times_updateCenters+1 {
		// 	break
		// }
		fmt.Printf("== UPDATE CENTERS ==\n")
		centers_ct_2 = elaborate.UpdateAllCenters_2(params, eval, eval_Innersum, points_ct_2, bool_ct_2, centers_ct_2, dimension, num_points, num_centers, eval_boot)
		// for i:=0;i<dimension;i++ {
		// 	printers.PrintPlaintext_Long(centers_ct_2[i], encoder, decryptor, 8, 2, 1)
		// }
	}
	end_time2 := time.Now()
	fmt.Printf("程序执行时间: %s\n", end_time2.Sub(start_time2))

	fmt.Printf("=============================== 输出 check 结果 ===============================\n")
	bool_matrix_2 := elaborate.DecryptBoolMatrix(bool_ct_2, encoder, decryptor, num_points, num_centers)
	labelSeq_2 := check.Transform_BoolMatrix_to_NumLabels(bool_matrix_2)
	fmt.Println(check.CalculateCorrelation_AllPermutations(labelSeq_benchmark, labelSeq_2, num_centers))
}