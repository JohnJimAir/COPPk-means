package utilities

import (
	"math"
	"math/rand"
)

func TransposeMatrix(matrix [][]float64) [][]float64 {
	// 获取矩阵的行数和列数
	rows := len(matrix)
	cols := len(matrix[0])

	// 创建一个新的二维切片来存储转置后的矩阵
	transposed := make([][]float64, cols)
	for i := range transposed {
		transposed[i] = make([]float64, rows)
	}

	// 执行转置操作
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}

func GenerateRandomNumbers_GivenInterval(interval_start int, interval_end int, num_need int) (randnum []int) {

	for len(randnum) < num_need {
		number := rand.Intn(interval_end - interval_start) + interval_start

		found := false
		for _, num := range randnum {
			if num == number {
				found = true
				break
			}
		}

		if !found {
			randnum = append(randnum, number)
		}
	}
	return randnum
}	

func GetSizeofBand(values []float64) (size_band float64) {
	
	min := values[0]
	max := values[0]
	for i:=0;i<len(values);i++ {
		if min > values[i] {
			min = values[i]
		}
		if max < values[i] {
			max = values[i]
		}
	}
	return max - min
}

func CountUniqueValues(values []int) (count int) {
	
	values_unique := make([]int, 0)
	values_unique = append(values_unique, values[0])
	for i:=1;i<len(values);i++ {
		found := false
		for j:=0;j<len(values_unique);j++ {
			if values[i] == values_unique[j] {
				found = true
				break
			}
		}
		if !found {
			values_unique = append(values_unique, values[i])
		}
	}
	return len(values_unique)
}

func Rescale(points_original [][]float64, scale float64) (points_rescaled [][]float64) {
	
	scale = 1.001*scale
	for i:=0;i<len(points_original);i++ {
		for j:=0;j<len(points_original[0]);j++ {
			points_original[i][j] = points_original[i][j] / math.Sqrt(scale)
		}
	}
	return points_original
}