package elaborate

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

// num_points * dimension + num_centers * dimension
func EncryptPointsAndCenters_AllInOne(params hefloat.Parameters, encoder *hefloat.Encoder, encryptor *rlwe.Encryptor, points [][]float64, centers [][]float64, dimension int, num_points int, num_centers int) (points_and_centers_ct *rlwe.Ciphertext) {
	
	var err error
	points_and_centers_values := make([]float64, params.MaxSlots())
	for i := 0; i < dimension; i++ {
		for j:=0;j<num_points;j++ {
			points_and_centers_values[ num_points*i+j ] = points[i][j]
		}
	}
	for i:=0;i<dimension;i++ {
		for j:=0;j<num_centers;j++ {
			points_and_centers_values[ num_points*dimension + num_centers*i+j ] = centers[i][j]
		}
	}

	points_and_centers_pt := hefloat.NewPlaintext(params, params.MaxLevel())
	if err = encoder.Encode(points_and_centers_values, points_and_centers_pt); err != nil {
		panic(err)
	}
	if points_and_centers_ct, err = encryptor.EncryptNew(points_and_centers_pt); err != nil {
		panic(err)
	}
	return
}

func DecryptBoolMatrix(bool_ct *rlwe.Ciphertext, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor, num_points int, num_centers int) (bool_matrix [][]float64) {
	
	values := make([]float64, bool_ct.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(bool_ct), values); err != nil {
		panic(err)
	}

	for i:=0;i<num_centers;i++ {
		bool_matrix = append(bool_matrix, values[i*num_points:(i+1)*num_points])
	}
	return bool_matrix
}