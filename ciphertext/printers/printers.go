package printers

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func PrintPlaintext(ciphertext *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor) (values []float64) {

	values = make([]float64, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		panic(err)
	}

	fmt.Printf("[[Values]]: ")
	for i := 0; i < 30; i++ {
		fmt.Printf("%16.15f ", values[i])
	}
	fmt.Printf("  ...   ...   ")
	for i := len(values)-6; i < len(values); i++ {
		fmt.Printf("%16.15f ", values[i])
	}
	fmt.Println()
	return values
}

func PrintPlaintext_Long(ciphertext *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor, length_oneLine int, num_lines_front int, num_lines_tail int) (values []float64) {

	values = make([]float64, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		panic(err)
	}

	fmt.Printf("[[Values]]: ")
	for i:=0;i<num_lines_front;i++ {
		for j:=0;j<length_oneLine;j++ {
			fmt.Printf("%16.15f ", values[i*length_oneLine + j])
		}
		fmt.Println()
	}

	fmt.Println("   ...   ...   ...   ")

	capacity_lines := len(values) / length_oneLine
	beginIndex := length_oneLine * (capacity_lines - num_lines_tail)
	for i:=0;i<num_lines_tail;i++ {
		for j:=0;j<length_oneLine;j++ {
			fmt.Printf("%16.15f ", values[beginIndex + i*length_oneLine + j])
		}
		fmt.Println()
	}

	beginIndex = length_oneLine * capacity_lines
	for i:=beginIndex;i<len(values);i++ {
		fmt.Printf("%16.15f ", values[i])
	}
	fmt.Println()
	return values
}

func PrintPlaintext_SimpleLong(ciphertext *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor, length_oneLine int) (values []float64) {
	num_lines_front := 2
	num_lines_tail := 1

	values = make([]float64, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		panic(err)
	}

	fmt.Printf("[[Values]]: ")
	for i:=0;i<num_lines_front;i++ {
		for j:=0;j<length_oneLine;j++ {
			fmt.Printf("%16.15f ", values[i*length_oneLine + j])
		}
		fmt.Println()
	}

	fmt.Println("   ...   ...   ...   ")

	capacity_lines := len(values) / length_oneLine
	beginIndex := length_oneLine * (capacity_lines - num_lines_tail)
	for i:=0;i<num_lines_tail;i++ {
		for j:=0;j<length_oneLine;j++ {
			fmt.Printf("%16.15f ", values[beginIndex + i*length_oneLine + j])
		}
		fmt.Println()
	}

	beginIndex = length_oneLine * capacity_lines
	for i:=beginIndex;i<len(values);i++ {
		fmt.Printf("%16.15f ", values[i])
	}
	fmt.Println()
	return values
}

func PrintMaxAndMin(ciphertext *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor) {

	var err error

	plaintext := decryptor.DecryptNew(ciphertext)
	values := make([]float64, ciphertext.Slots())
	if err = encoder.Decode(plaintext, values); err != nil {
		panic(err)
	}

	max := values[0]
	min := values[0]
	for i := range values {
		if max < values[i] {
			max = values[i]
		}
		if min > values[i] {
			min = values[i]
		}
	}
	fmt.Printf("Max: %20.12f \n", max)
	fmt.Printf("Min: %20.12f \n", min)
}

func PrintScaleAndLevel(ciphertext *rlwe.Ciphertext) {
	ctScale := &ciphertext.Scale.Value // We need to access the pointer to have it display correctly in the command line
	fmt.Printf("Scale: %f and Level: %d \n", ctScale, ciphertext.Level())
}