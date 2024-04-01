package main

import (
	"fmt"
	"goisbest/plaintext"
	"goisbest/plaintext/check"
	"goisbest/utilities"
)

func main(){

	// file_directory := "/home/chenjingwei/z_dataset"
	// num_points := 4096
	// dimension := 16
	// interval_start, interval_end := -1.0, 1.0
	// num_centers := 4
	// points, centers, scale := utilities.ReadPEGASUS(file_directory, num_points, dimension, interval_start, interval_end, num_centers)


	filepath := "/home/chenjingwei/z_dataset/Lsun.csv"
	points, dimension, num_points, num_centers, scale, labelSeq_benchmark := utilities.ReadFCPS(filepath)
	points = utilities.Rescale(points, scale)
	index_centers := utilities.GenerateRandomNumbers_GivenInterval(0, num_points, num_centers)
	// index_centers := make([]int, num_centers)
	// for i := 0; i < num_centers; i++ {
	// 	index_centers[i] = i
	// }
	centers := plaintext.ExtractCentersFromPoints(points, index_centers)
	

	centers_notstabilized := centers
	centers_stabilized := centers
	var bool_matrix_notstabilized [][]float64
	var bool_matrix_stabilized [][]float64

	// begin computation
	for iters:=0;iters<10;iters++{
		fmt.Printf("====== NOW AT THE %dth ITERATION ======\n", iters)

		// fmt.Println("== NOT STABILIZED ==")
		distances_notstabilized := plaintext.Compute_Distances(points, centers_notstabilized, dimension, num_points, num_centers)

		bool_matrix_notstabilized = plaintext.Compare_Distances(distances_notstabilized, num_points, num_centers, "Exactly")
		// fmt.Println(bool_matrix_notstabilized)

		centers_notstabilized = plaintext.Update_Centers_NotStabilized(points, bool_matrix_notstabilized, num_points, num_centers, dimension)
		// fmt.Println(centers_notstabilized)
		
		// fmt.Println("== STABILIZED ==")
		distances_stabilized := plaintext.Compute_Distances(points, centers_stabilized, dimension, num_points, num_centers)

		bool_matrix_stabilized = plaintext.Compare_Distances(distances_stabilized, num_points, num_centers, "NotExactly")
		// fmt.Println(bool_matrix_stabilized)

		centers_stabilized = plaintext.Update_Centers_Stabilized(points, bool_matrix_stabilized, centers_stabilized, num_points, num_centers, dimension)
		// fmt.Println(centers_stabilized)		
	}
	fmt.Println(centers_stabilized)



	labelSeq_notstabilized := check.Transform_BoolMatrix_to_NumLabels(bool_matrix_notstabilized)
	labelSeq_stabilized := check.Transform_BoolMatrix_to_NumLabels(bool_matrix_stabilized)
	fmt.Println(check.CalculateCorrelation_AllPermutations(labelSeq_benchmark, labelSeq_notstabilized, num_centers))
	fmt.Println(check.CalculateCorrelation_AllPermutations(labelSeq_benchmark, labelSeq_stabilized, num_centers))
	fmt.Println(check.CalculateCorrelation_AllPermutations(labelSeq_notstabilized, labelSeq_stabilized, num_centers))





	
}