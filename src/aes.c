/*!
 * \file
 * \brief AES functions implementation
 */
#include "aes.h"

#include "matrices.h"

#include <stdlib.h>
#include <stdio.h>
#include <math.h>

void aesResetGlobalData(aes_global_t * data)
{
	data->in_data = NULL;
	data->in_size = 0;
	data->in_blocks = 0;

	data->round_key = NULL;
}

void aesFreeGlobalData(aes_global_t * data)
{
	free(data->in_data);
	free(data->round_key);
	aesResetGlobalData(data);
}

void aesInitGlobalData(aes_global_t * data, int key_bits)
{
	data->Nk = key_bits / 32;
	data->Nr = data->Nk + 6;
	data->Nb = 4;
	data->block_size = 16;
	data->round_key_size = data->Nb * (data->Nr+1) * 4;
}

void aesPrepareCipherFromFile(aes_global_t * data, const char * in_file) {
	FILE * in_f;

	in_f = fopen(in_file, "rb");

	if (in_f == NULL)
		perror("Can't open input file!");

	// get input file size
	fseek(in_f, 0, SEEK_END);
	data->in_size = ftell(in_f);
	data->in_blocks = (uint32_t) ceil(1.0 * data->in_size / data->block_size);
	fseek(in_f, 0, SEEK_SET);

	// allocate memory for input buffer
	data->in_data = (uint8_t *) malloc(data->in_blocks * data->block_size);
	if (data->in_data == NULL)
	{
		fclose(in_f);
		perror("Can't allocate memory for input buffer!");
	}

	// load file content into buffer
	if (data->in_size != fread(data->in_data, sizeof(uint8_t), data->in_size,
			in_f))
	{
		free(data->in_data);
		fclose(in_f);
		perror("Can't read input file to buffer!");
	}

	fclose(in_f);
}

void aesStoreResult(aes_global_t * data, const char * out_file)
{
	FILE * out_f;

	out_f = fopen(out_file, "wb");

	if (out_f == NULL)
		perror("Can't open output file!");

	// write output buffer into file
	if (data->in_size != fwrite(data->in_data, sizeof(uint8_t), data->in_size,
			out_f))
	{
		fclose(out_f);
		perror("Can't read input file to buffer!");
	}

	fclose(out_f);
}

void aesKeyExpansion(aes_global_t * data, uint8_t * key)
{
    int i,j;
    uint8_t temp[4], k;
    uint8_t * RoundKey = (uint8_t*)malloc(sizeof(uint8_t) * data->round_key_size * 4);

    // The first round key is the key itself.
    for(i=0; i < data->Nk; i++){
        RoundKey[i*4  ] = key[i*4  ];
        RoundKey[i*4+1] = key[i*4+1];
        RoundKey[i*4+2] = key[i*4+2];
        RoundKey[i*4+3] = key[i*4+3];
    }

    // All other round keys are found from the previous round keys.
    while (i < data->round_key_size){

        for(j=0;j<4;j++){
            temp[j] = RoundKey[(i-1) * 4 + j];
        }

        if (i % data->Nk == 0){
            // This function rotates the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                temp[0]=sbox[temp[0]];
                temp[1]=sbox[temp[1]];
                temp[2]=sbox[temp[2]];
                temp[3]=sbox[temp[3]];
            }

            temp[0] =  temp[0] ^ Rcon[i/data->Nk];
        }
        else if ( (data->Nk > 6) && (i % data->Nk == 4) ){
            // Function Subword()
            {
                temp[0]=sbox[temp[0]];
                temp[1]=sbox[temp[1]];
                temp[2]=sbox[temp[2]];
                temp[3]=sbox[temp[3]];
            }
        }
        RoundKey[i*4+0] = RoundKey[(i - data->Nk)*4+0] ^ temp[0];
        RoundKey[i*4+1] = RoundKey[(i - data->Nk)*4+1] ^ temp[1];
        RoundKey[i*4+2] = RoundKey[(i - data->Nk)*4+2] ^ temp[2];
        RoundKey[i*4+3] = RoundKey[(i - data->Nk)*4+3] ^ temp[3];
        i++;
    }

    data->round_key = RoundKey;
}





void aesFillState(aes_state_t * state, uint8_t * data) {
	int i;
	for (i = 0; i < 4; ++i) {
		state->s[ 0 + i] = data[4*i + 0];
		state->s[ 4 + i] = data[4*i + 1];
		state->s[ 8 + i] = data[4*i + 2];
		state->s[12 + i] = data[4*i + 3];
	}
}




void aesAddRoundKey(aes_global_t * data, aes_state_t * state, int round){

    /*int i;
    uint32_t *s32 = (uint32_t*)state->s;
    uint32_t *r32 = (uint32_t*)data->round_key;
    int Nb = data->Nb;

   	s32[0] ^= r32[round * Nb + 0];
   	s32[1] ^= r32[round * Nb + 1];
   	s32[2] ^= r32[round * Nb + 2];
   	s32[3] ^= r32[round * Nb + 3];*/

	int i,j;
	for(i=0; i<4; i++){
		for(j=0; j<4; j++){
			state->s[j*4+i] ^= data->round_key[round * data->Nb * 4 + i * data->Nb + j];
		}
	}
}


void aesSubBytes(aes_state_t * state) {
	uint8_t * s = state->s;
    int i;
    for(i=0; i<16; i++) {
        s[i] = sbox[s[i]];
    }
}

uint32_t rol(const uint32_t value, int places) {
	return ((value << places) & 0xFFFFFFFF) | ((value >> (sizeof(uint32_t)*8 - places) & 0xFFFFFFFF));
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void aesShiftRows(aes_state_t * state) {

    uint32_t *s32 = (uint32_t*)state->s;

    s32[1] = rol(s32[1], 24);
    s32[2] = rol(s32[2], 16);
    s32[3] = rol(s32[3], 8);
}

// MixColumns function mixes the columns of the state matrix
// The method used may look complicated, but it is easy if you know the underlying theory.
// Refer the documents specified above.
void aesMixColumns(aes_state_t * state) {
	int i;
	uint8_t * s = state->s;
	for (i = 0; i < 4; ++i) {
        uint8_t a[4];
        uint8_t b[4];
        uint8_t c;
        uint8_t h;
		/* The array 'a' is simply a copy of the input array 'r'
			 * The array 'b' is each element of the array 'a' multiplied by 2
			 * in Rijndael's Galois field
			 * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
		for(c=0;c<4;c++) {
			a[c] = s[c*4+i];
			h = a[c] & 0x80; /* hi bit */
			b[c] = a[c] << 1;
			if(h == 0x80)
				b[c] ^= 0x1B; /* Rijndael's Galois field */
		}
		s[0+i] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
		s[4+i] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
		s[8+i] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
		s[12+i] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
	}
}

void aesCipherBlock(aes_global_t * data, aes_state_t * state) {
    int i, j, rd=0;

    // Add the First round key to the state before starting the rounds.
    aesAddRoundKey(data, state, 0);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(rd = 1; rd < data->Nr; rd++)
    {
        aesSubBytes(state);
        aesShiftRows(state);
        aesMixColumns(state);
        aesAddRoundKey(data, state, rd);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    aesSubBytes(state);
    aesShiftRows(state);
    aesAddRoundKey(data, state, data->Nr);
}

aes_state_t aesCipherCounter(aes_global_t * data, uint32_t ctr) {
    aes_state_t state;
    uint32_t d[4];
    uint32_t *s32 = (uint32_t*)state.s;

    // prepare counter value
    d[0] = data->nonce_0;
    d[1] = data->nonce_1;
    d[2] = 0;
    d[3] = ctr;

    aesFillState(&state, (uint8_t*)d);

    aesCipherBlock(data, &state);

    return state;
}

void aesCipher(aes_global_t * data, uint32_t c)
{
	uint32_t i;
	uint8_t * in_ptr = data->in_data;
	uint32_t * in_ptr32 = (uint32_t*) in_ptr;

	uint32_t in_size = data->in_size;
	uint32_t in_blocks = data->in_blocks;

	#pragma omp parallel for default(none) private(i) shared(in_blocks, in_ptr32, c)
	for (i = 0; i < in_blocks; ++i)
	{
		in_ptr32[4 * i    ] = in_ptr32[4 * i    ] ^ c;
		in_ptr32[4 * i + 1] = in_ptr32[4 * i + 1] ^ c;
		in_ptr32[4 * i + 2] = in_ptr32[4 * i + 2] ^ c;
		in_ptr32[4 * i + 3] = in_ptr32[4 * i + 3] ^ c;
	}
}
