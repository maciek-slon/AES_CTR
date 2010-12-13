#!/bin/bash

# set size of test file
if [ -n "$1" ]
then
	filesize=$1
else
	filesize=10
fi

# set number of cipher/decipher repeats for each process count
if [ -n "$2" ]
then
	repeats=$2
else
	repeats=10
fi

# set maximum number of processes allowed
if [ -n "$3" ]
then
	max_threads=$3
else
	max_threads=16
fi

# generate random test file of given size
filename=randomfile

echo "Generating random $filesize MB test file"
dd if=/dev/urandom of=$filename bs=1M count=$filesize

# test program for each allowed number of threads (1, 2, 4, 8, ...)
echo "Testing OpenMP ($repeats repeats, max $max_threads threads)..."
for (( t=1; t<=$max_threads; t*=2 ))
do
	echo "$t processes..."
	#export OMP_NUM_THREADS=$t
	
	for (( c=1; c<=$repeats; c++ ))
	do
		mpiexec.openmpi -np $t -machinefile machine.openmpi aes_mpi -c -g ../lib/libhash_md5.so -k 1234 -o $filename.out -s 128 $filename
		mpiexec.openmpi -np $t -machinefile machine.openmpi aes_mpi -d -g ../lib/libhash_md5.so -k 1234 -o $filename.or -s 128 $filename.out
		diff $filename $filename.or
	done

done

# remove temporary files
rm $filename 
rm $filename.or
rm $filename.out
