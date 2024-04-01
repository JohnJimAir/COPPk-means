package plaintext

import (
	"fmt"
	"goisbest/utilities/coefficients"

	"os"
)

func Compare_Exactly(input_1 float64, input_2 float64) (output_1 float64, output_2 float64) {
	if input_1 < input_2 {
		return 1.0, 0.0
	} else if input_1 > input_2 {
		return 0.0, 1.0
	} else {
		return 0.5, 0.5
	}
}

func Compare_NotExactly(input_1 float64, input_2 float64) (output_1 float64, output_2 float64) {
	input := (input_1 - input_2)
	output := Sign_Kernel(input)
	output_2 = (output + 1.0) / 2.0
	output_1 = 1.0 - output_2
	return output_1, output_2
}

func Sign_Kernel(input float64) (output float64) {
	output = Sign_3(input)
	output = Sign_7(output)
	output = Sign_15(output)
	// output = Sign_15(output)
	output = Sign_15(output)
	return output
}

func Sign_15(input float64) (output float64) {
	return evaluatePolynomial(coefficients.Coeffs_n15, input)
}

func Sign_7(input float64) (output float64) {
	return evaluatePolynomial(coefficients.Coeffs_n7, input)
}

func Sign_3(input float64) (output float64) {
	return evaluatePolynomial(coefficients.Coeffs_n3, input)
}

func evaluatePolynomial(coefficients []float64, x float64) float64 {
	result := 0.0
	power := 1.0

	for _, coefficient := range coefficients {
		result += coefficient * power
		power *= x
	}
	return result
}

func Compare_Oneline(values []float64, exact string) (results []float64) {
	if exact != "Exactly" && exact != "NotExactly" {
		fmt.Println("Exactly or NotExactly ?!")
		os.Exit(1)
	}

	length := len(values)
	matrix_onehot := make([][]float64, length)
    for i := range matrix_onehot {
        matrix_onehot[i] = make([]float64, length)
    }

	for i:=0;i<length;i++ {
		matrix_onehot[i][i] = 1.0
	}
	for i:=0;i<length;i++ {
		for j:=i+1;j<length;j++ {
			if exact == "Exactly" {
				matrix_onehot[i][j], matrix_onehot[j][i] = Compare_Exactly(values[i], values[j])
			} else {
				matrix_onehot[i][j], matrix_onehot[j][i] = Compare_NotExactly(values[i], values[j])
			} 
		}
	}

	results = make([]float64, length)
	for i:=0;i<length;i++ {
		results[i] = 1.0
		for j:=0;j<length;j++ {
			results[i] *= matrix_onehot[i][j]
		}
	}
	return results
}