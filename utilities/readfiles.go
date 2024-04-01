package utilities

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ReadFloatArrayFromFile(filename string) ([][]float64, error) {
	var result [][]float64

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 显式设置Scanner的缓冲区大小
	scanner := bufio.NewScanner(file)
	const maxScanTokenSize = 64 * 20480 // 设置为所需的最大行大小
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		line := scanner.Text()
		values := strings.Fields(line)
		row := make([]float64, len(values))

		for i, value := range values {
			num, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return nil, err
			}
			row[i] = num
		}
		result = append(result, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// Not include the first line
func ReadCSVtoFloat(filePath string) ([][]float64, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	result := make([][]float64, len(records)-1)
	for i := 1; i < len(records); i++ {
		result[i-1] = make([]float64, len(records[i]))
		for j := 0; j < len(records[i]); j++ {
		
			value, err := strconv.ParseFloat(records[i][j], 64)
			if err != nil {
				return nil, err
			}
			result[i-1][j] = value
		}
	}
	result = TransposeMatrix(result)
	return result, nil
}

func ReadFCPS(filepath string) (points [][]float64, dimension int, num_points int, num_centers int, scale float64, labelSeq_benchmark []int) {

	data_includeLabel, err := ReadCSVtoFloat(filepath)
	if err != nil {
		panic(err)
	}
	points = data_includeLabel[1:]
	dimension = len(points)
	num_points = len(points[0])
	scale = 0.0
	for i:=0;i<dimension;i++ {
		scale += GetSizeofBand(points[i]) * GetSizeofBand(points[i])
	}
	scale += 1.0

	labelSeq_benchmark = make([]int, num_points)
	for i, value := range data_includeLabel[0] {
		labelSeq_benchmark[i] = int(value)
	}

	num_centers = CountUniqueValues(labelSeq_benchmark)

	return points, dimension, num_points, num_centers, scale, labelSeq_benchmark
}

func ReadPEGASUS(file_directory string, num_points int, dimension int, interval_start float64, interval_end float64, num_centers int) (points [][]float64, centers [][]float64, scale float64) {

	length_interval := interval_start - interval_end
	scale = float64(length_interval*length_interval * float64(dimension))

	filepath := file_directory + "/RandNumbers_" + strconv.Itoa(num_points) + "_" + strconv.Itoa(dimension) + "_" + strconv.FormatFloat(interval_start, 'f', 1, 64) + "-" + strconv.FormatFloat(interval_end, 'f', 1, 64) +  "_.txt"
	points, err := ReadFloatArrayFromFile(filepath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// index_centers := make([]int, num_centers)
	// for i := 0; i < num_centers; i++ {
	// 	index_centers[i] = i
	// }
	index_centers := GenerateRandomNumbers_GivenInterval(0, num_points, num_centers)
	for _, row := range points {
		centers_onedim := make([]float64, 0)
		for _, index := range index_centers {
			centers_onedim = append(centers_onedim, row[index])
		}
        centers = append(centers, centers_onedim)
    }

	return points, centers, scale
}