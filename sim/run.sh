#! /bin/bash

#as_nums=( 20 40 60 80 100 200 300 400 500 600 700 800 900 1000 )
as_nums=( 500 600 700 800 900 1000 )

FILE=result_w_sgx
PROGRAM=rs_w_sgx

touch $FILE

for as_num in "${as_nums[@]}"
do
    echo >> $FILE 2>&1
    echo as_num $as_num >> $FILE 2>&1
    for j in `seq 1 10`
    do
        echo >> $FILE 2>&1
        echo round $j >> $FILE 2>&1
        ./$PROGRAM -a conf/as_peer_$as_num.conf -t conf/trace_large_$as_num.conf >> $FILE 2>&1
    done
done
