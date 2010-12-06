#!/bin/bash

if [ -n "$1" ]
then
	filesize=$1
else
	filesize=10
fi

if [ -n "$2" ]
then
	repeats=$2
else
	repeats=10
fi

filename=/tmp/randomfile

echo "Generating random test $filesize MB file"
dd if=/dev/urandom of=$filename bs=1M count=$filesize


echo "Testing OpenMP..."
for t in 1 2 4 8 16
do
	echo "$t threads..."
	export OMP_NUM_THREADS=$t
	
	for (( c=1; c<=$repeats; c++ ))
	do
		./aes_ctr -c -g ../lib/libhash_md5.so -k 1234 -o $filename.out -s 192 $filename
		./aes_ctr -d -g ../lib/libhash_md5.so -k 1234 -o $filename.or -s 192 $filename.out
		diff randomfile randomfile.or
	done

done

rm $filename.or
rm $filename.out