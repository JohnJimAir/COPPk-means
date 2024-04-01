#!/bin/bash
#SBATCH -J Lattigo
#SBATCH -p defq
#SBATCH -A chenjingwei
#SBATCH -N 1
#SBATCH -w node01
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=60G

go run main.go

# 感觉都不如最开始在陈老师办公室电脑上的快，之前在陈老师电脑上一轮迭代是一分钟不到，而且那个时候一轮迭代还是4次bootstrap，是因为那个电脑的cpu非常猛吗？