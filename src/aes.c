/*!
 * \file
 * \brief AES functions implementation
 */
#include "aes.h"

#include <stdlib.h>
#include <stdio.h>
#include <math.h>


void aesResetGlobalData(aes_global_t * data) {
	data->in_data = NULL;
	data->in_size = 0;
	data->in_blocks = 0;
}


void aesFreeGlobalData(aes_global_t * data) {
	free(data->in_data);
	aesResetGlobalData(data);
}


void aesInitGlobalData(aes_global_t * data, const char * in_file, int key_bits) {
	FILE * in_f;

	data->Nk = key_bits / 32;
	data->Nr = data->Nk + 6;
	data->Nb = 4;
	data->block_size = 16;

	in_f = fopen(in_file, "rb");

	if (in_f == NULL)
		perror("Can't open input file!");

	// get input file size
	fseek(in_f, 0, SEEK_END);
	data->in_size = ftell(in_f);
	data->in_blocks = (uint32_t)ceil(1.0 * data->in_size / data->block_size);
	fseek(in_f, 0, SEEK_SET);

	// allocate memory for input buffer
	data->in_data = (uint8_t *)malloc(data->in_blocks * data->block_size);
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
}


void aesStoreResult(aes_global_t * data, const char * out_file) {
	FILE * out_f;

	out_f = fopen(out_file, "wb");

	if (out_f == NULL)
		perror("Can't open output file!");

	// write output buffer into file
	if (data->in_size != fwrite(data->in_data, sizeof(uint8_t), data->in_size, out_f)){
		fclose(out_f);
		perror("Can't read input file to buffer!");
	}

	fclose(out_f);
}


void aesCipher(aes_global_t * data, uint32_t c) {
	uint32_t i;
	uint8_t * in_ptr = data->in_data;
	uint32_t * in_ptr32 = (uint32_t*)in_ptr;

	uint32_t in_size = data->in_size;
	uint32_t in_blocks = data->in_blocks;

	#pragma omp parallel for default(none) private(i) shared(in_blocks, in_ptr32, c)
	for (i = 0; i < in_blocks; ++i) {
		in_ptr32[4*i  ] = in_ptr32[4*i  ] ^ c;
		in_ptr32[4*i+1] = in_ptr32[4*i+1] ^ c;
		in_ptr32[4*i+2] = in_ptr32[4*i+2] ^ c;
		in_ptr32[4*i+3] = in_ptr32[4*i+3] ^ c;
	}
}
