/*
 * main.cpp
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

// export OMP_NUM_THREADS=N

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <omp.h>
#include <math.h>

typedef struct aes_global_s {
	// Data buffers
	/// Input data
	uint8_t *in_data;
	/// Size of input data
	uint32_t in_size;
	/// Output (ciphered) data
	uint8_t *out_data;
	/// Size of output data
	uint32_t out_size;

	// AES specific parameters
	/// Nk - Number of 32 bit words in Key;
	int Nk;
	/// Nr - Number of rounds in cypher;
	int Nr;
	/// Nb - The number of columns comprising a state in AES;
	int Nb;
} aes_global_t;

void aesResetGlobalData(aes_global_t * data) {
	data->in_data = NULL;
	data->in_size = 0;
	data->out_data = NULL;
	data->out_size = 0;
}

void aesFreeGlobalData(aes_global_t * data) {
	free(data->in_data);
	free(data->out_data);
	aesResetGlobalData(data);
}

/*!
 * Fill all fields of global AES data.
 *
 * @param data pointer to struct to be filled
 * @param in_file name of file with input data to be ciphered
 * @param key_bits number of bits in key, must be on of 128, 192 or 256
 */
void aesInitGlobalData(aes_global_t * data, const char * in_file, int key_bits) {
	FILE * in_f;

	data->Nk = key_bits / 32;
	data->Nr = data->Nk + 6;
	data->Nb = 4;

	in_f = fopen(in_file, "rb");

	if (in_f == NULL)
		perror("Can't open input file!");

	// get input file size
	fseek(in_f, 0, SEEK_END);
	data->in_size = ftell(in_f);
	fseek(in_f, 0, SEEK_SET);

	// allocate memory for input buffer
	data->in_data = (uint8_t *)malloc(data->in_size);
	if (data->in_data == NULL) {
		fclose(in_f);
		perror("Can't allocate memory for input buffer!");
	}

	// load file content into buffer
	if (data->in_size != fread(data->in_data, sizeof(uint8_t), data->in_size, in_f)){
		free(data->in_data);
		fclose(in_f);
		perror("Can't read input file to buffer!");
	}

	fclose(in_f);

	// output data buffer size is equal to input buffer size
	data->out_size = data->in_size;

	// allocate memory for output buffer
	data->out_data = (uint8_t *)malloc(data->out_size);
	if (data->out_data == NULL) {
		free(data->in_data);
		perror("Can't allocate memory for output buffer!");
	}

}

void aesStoreResult(aes_global_t * data, const char * out_file) {
	FILE * out_f;

	out_f = fopen(out_file, "wb");

	if (out_f == NULL)
		perror("Can't open output file!");

	// write output buffer into file
	if (data->out_size != fwrite(data->in_data, sizeof(uint8_t), data->in_size, out_f)){
		fclose(out_f);
		perror("Can't read input file to buffer!");
	}

	fclose(out_f);
}

void aesCipher(aes_global_t * data, uint8_t c) {
	uint32_t i;
	uint8_t * in_ptr = data->in_data;
	uint32_t in_size = data->in_size;


	#pragma omp parallel for default(none) private(i) shared(in_size, in_ptr, c)
	for (i = 0; i < in_size; ++i) {
		in_ptr[i] = in_ptr[i] ^ c;
	}
}

int main(int argc, char** argv) {
	int key_size;
	aes_global_t data;
	volatile uint8_t c = 0xAA;
	int i;

	if(argc < 4){
		printf("Usage: AES_CTR <key_length> <input_file> <output_file>");
		return(0);
	}

	key_size = atoi(argv[1]);
	if(key_size!=128 && key_size!=192 && key_size!=256){
		printf("Key should be 128, 192 or 256 bit only\n");
		return(0);
	}

	aesResetGlobalData(&data);
	aesInitGlobalData(&data, argv[2], key_size);

	for (i=0; i < 20; ++i)
		aesCipher(&data, c);


	aesStoreResult(&data, argv[3]);
	aesFreeGlobalData(&data);

//	copyKeyFromFile(key);
//
//	readInputData(in);
//
//	// The KeyExpansion routine must be called before encryption.
//	KeyExpansion();
//
//	Cipher_CTR();
//
//	copyOutToIn();
//
//	InvCipher_CTR();
//
//	writeOutputData(out);

	return (0);
}

