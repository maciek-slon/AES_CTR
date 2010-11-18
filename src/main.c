/*
 * main.cpp
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

/**
 * Czasy działania:
 * Jeden wątek:
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ export OMP_NUM_THREADS=1
 *		szkudi@szkudi:~/workspace/AES_CTR/Debug$ time ./AES_CTR 128 key xxx.mp3
 *		Długość ciągu wejsciowego: 5465234
 *		Liczba blokow: 341578
 *		DEC:  Długość ciągu wejsciowego: 5465264
 *		Liczba blokow: 341579
 *
 *		real	0m6.333s
 *		user	0m3.660s
 *		sys	0m2.670s
 *
 * Dwa wątki:
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ export OMP_NUM_THREADS=2
 *		szkudi@szkudi:~/workspace/AES_CTR/Debug$ time ./AES_CTR 128 key xxx.mp3
 * 		Długość ciągu wejsciowego: 5465234
 * 		Liczba blokow: 341578
 * 		DEC:  Długość ciągu wejsciowego: 5465264
 * 		Liczba blokow: 341579
 *
 * 		real	0m6.144s
 * 		user	0m6.710s
 * 		sys	0m5.560s
 *
 * 	Trzy wątki:
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ export OMP_NUM_THREADS=3
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ time ./AES_CTR 128 key xxx.mp3
 * 		Długość ciągu wejsciowego: 5465234
 * 		Liczba blokow: 341578
 * 		DEC:  Długość ciągu wejsciowego: 5465264
 * 		Liczba blokow: 341579
 *
 * 		real	0m6.092s
 * 		user	0m12.720s
 * 		sys	0m5.500s
 *
 * Cztery watki:
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ export OMP_NUM_THREADS=4
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ time ./AES_CTR 128 key xxx.mp3
 * 		Długość ciągu wejsciowego: 5465234
 * 		Liczba blokow: 341578
 * 		DEC:  Długość ciągu wejsciowego: 5465264
 * 		Liczba blokow: 341579
 *
 * 		real	0m19.706s
 * 		user	0m42.920s
 * 		sys	0m18.990s
 *
 * Dziesięc watków:
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ export OMP_NUM_THREADS=10
 * 		szkudi@szkudi:~/workspace/AES_CTR/Debug$ time ./AES_CTR 128 key xxx.mp3
 * 		Długość ciągu wejsciowego: 5465234
 * 		Liczba blokow: 341578
 * 		DEC:  Długość ciągu wejsciowego: 5465264
 * 		Liczba blokow: 341579
 *
 *		real	0m28.513s
 * 		user	0m18.390s
 *		sys	0m30.040s
 */

#include "AES.h"
#include <stdio.h>


int main(int argc, char** argv){

	FILE* in, *out, *key;
	FILE* third;

	if(argc < 4){
		printf("Usage: AES_CTR <key_length> <key_file> <input_file> [<output_file>]\nKey length should be 128, 192, or 256 bit.\nIf no output filename defined, default name \"output\".\n");\
		return(0);
	}

	Nr = atoi(argv[1]);
	if(Nr!=128 && Nr!=192 && Nr!=256){
		printf("Key should be 128, 192 or 256 bit only\n");
		return(0);
	}

	key = fopen(argv[2], "rb");
	if(key == NULL){
		printf("Cannot open key file!!\n");
		return(0);
	}

	in = fopen(argv[3], "rb");
	if(in == NULL){
		printf("Cannot open input data file!!!\n");
		return (0);
	}

	if(argc > 4)
		out = fopen(argv[4], "wb+");
	else
		out = fopen("output", "wb+");

	if(out == NULL){
		printf("Cannot open/create output file!!\n");
		return (0);
	}

	third = fopen("third", "wb+");

	// Calculate Nk and Nr from the received value.
	Nk = Nr / 32;
	Nr = Nk + 6;
	Nb = 4;

	copyKeyFromFile(key);

	// The KeyExpansion routine must be called before encryption.
	KeyExpansion();

	Cipher_CTR(in, out);

	InvCipher_CTR(out, third);

	return (0);
}

