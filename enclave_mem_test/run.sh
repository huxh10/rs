#! /bin/bash

mem_size_m=( 1 2 4 6 8 10 16 24 32 48 64 72 80 84 88 92 96 104 112 120 128 256 512 1024 )

FILE=result_w_sgx
PROGRAM=mem_test

touch $FILE

for ms in "${mem_size_m[@]}"
do
    echo >> $FILE 2>&1
    echo mem_size $ms MB >> $FILE 2>&1
    ./$PROGRAM -a 1000000 -m $ms >> $FILE 2>&1
done
