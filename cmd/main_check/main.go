package main

import (
	"fmt"
	"goisbest/plaintext/check"
)

func main(){
	seq1 := []int{2,2,2,2,1,3}
	seq2 := []int{1,1,1,2,1,3}
	num_labels := 3

	ratio := check.CalculateCorrelation_AllPermutations(seq1, seq2, num_labels)
	fmt.Println(ratio)

}
