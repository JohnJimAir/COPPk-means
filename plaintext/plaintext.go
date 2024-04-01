package plaintext

import (
	"fmt"
	"goisbest/utilities"
	"math"
	"os"
)

func ExtractCentersFromPoints(points [][]float64, index_centers []int) (centers [][]float64) {

    for _, row := range points {
		centers_onedim := make([]float64, 0)
		for _, index := range index_centers {
			centers_onedim = append(centers_onedim, row[index])
		}
        centers = append(centers, centers_onedim)
    }
	return centers
}

func Compute_Distances(points [][]float64, centers [][]float64, dimension int, num_points int, num_centers int) (distances [][]float64) {
	// 先算对于一个中心点的距离，这是distances的第一个元素。所以说循环的最外层是num_centers，然后是num_points，最里面是dimension
	distances = make([][]float64, num_centers)
    for i := range distances {
        distances[i] = make([]float64, num_points)
    }
	for i:=0;i<num_centers;i++ {
		for j:=0;j<num_points;j++ {
			for k:=0;k<dimension;k++ {
				distances[i][j] += math.Pow(points[k][j] - centers[k][i], 2)
			}
		}
	}
	return distances
}

func Compare_Distances(distances [][]float64, num_points int, num_centers int, exact string) (bool_matrix [][]float64) {
	if exact != "Exactly" && exact != "NotExactly" {
		fmt.Println("Exactly or NotExactly ?!")
		os.Exit(1)
	}

	distances_t := utilities.TransposeMatrix(distances)

	bool_matrix_t := make([][]float64, num_points)
    for i := range bool_matrix_t {
        bool_matrix_t[i] = make([]float64, num_centers)
    }

	for i:=0;i<num_points;i++ {
			bool_matrix_t[:][i] = Compare_Oneline(distances_t[:][i], exact)
	}
	return utilities.TransposeMatrix(bool_matrix_t)
}

func Update_Centers_Stabilized(points [][]float64, bool_matrix [][]float64, centers_old [][]float64, num_points int, num_centers int, dimension int) (centers_new [][]float64) {
	
	centers_new = make([][]float64, dimension)
    for i := range centers_new {
        centers_new[i] = make([]float64, num_centers)
    }

	for i:=0;i<num_centers;i++ {
		for j:=0;j<dimension;j++ {
			sum := 0.0
			for k:=0;k<num_points;k++ {
				sum += points[j][k] * bool_matrix[i][k] + centers_old[j][i] * (1.0-bool_matrix[i][k])
			}
			centers_new[j][i] = sum / float64(num_points)
		}
	}
	return centers_new
}

func Update_Centers_NotStabilized(points [][]float64, bool_matrix [][]float64, num_points int, num_centers int, dimension int) (centers_new [][]float64) {
	
	centers_new = make([][]float64, dimension)
    for i := range centers_new {
        centers_new[i] = make([]float64, num_centers)
    }

	for i:=0;i<num_centers;i++ {
		for j:=0;j<dimension;j++ {
			sum := 0.0
			count := 0.0
			for k:=0;k<num_points;k++ {
				sum += points[j][k] * bool_matrix[i][k]
				count += bool_matrix[i][k]
			}
			centers_new[j][i] = sum / count
		}
	}
	return centers_new
}