/*
 * AES.cpp
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

#include "AES.h"


// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// Multiplty is a macro used to multiply numbers in the field GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))


uint8_t getSBoxValue(int num)
{
    return sbox[num];
}

uint8_t getSBoxInvert(int num){
	return rsbox[num];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to encrypt the states.
void KeyExpansion()
{
    int i,j;
    uint8_t temp[4],k;

    // The first round key is the key itself.
    for(i=0;i<Nk;i++)
    {
        RoundKey[i*4]=Key[i*4];
        RoundKey[i*4+1]=Key[i*4+1];
        RoundKey[i*4+2]=Key[i*4+2];
        RoundKey[i*4+3]=Key[i*4+3];
    }

    // All other round keys are found from the previous round keys.
    while (i < (Nb * (Nr+1)))
    {
        for(j=0;j<4;j++)
        {
            temp[j]=RoundKey[(i-1) * 4 + j];
        }
        if (i % Nk == 0)
        {
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
                temp[0]=getSBoxValue(temp[0]);
                temp[1]=getSBoxValue(temp[1]);
                temp[2]=getSBoxValue(temp[2]);
                temp[3]=getSBoxValue(temp[3]);
            }

            temp[0] =  temp[0] ^ Rcon[i/Nk];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            // Function Subword()
            {
                temp[0]=getSBoxValue(temp[0]);
                temp[1]=getSBoxValue(temp[1]);
                temp[2]=getSBoxValue(temp[2]);
                temp[3]=getSBoxValue(temp[3]);
            }
        }
        RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0];
        RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1];
        RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2];
        RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3];
        i++;
    }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(int round)
{
    int i,j;
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes()
{
    int i,j;
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            state[i][j] = getSBoxValue(state[i][j]);

        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows()
{
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp=state[1][0];
    state[1][0]=state[1][1];
    state[1][1]=state[1][2];
    state[1][2]=state[1][3];
    state[1][3]=temp;

    // Rotate second row 2 columns to left
    temp=state[2][0];
    state[2][0]=state[2][2];
    state[2][2]=temp;

    temp=state[2][1];
    state[2][1]=state[2][3];
    state[2][3]=temp;

    // Rotate third row 3 columns to left
    temp=state[3][0];
    state[3][0]=state[3][3];
    state[3][3]=state[3][2];
    state[3][2]=state[3][1];
    state[3][1]=temp;
}



// MixColumns function mixes the columns of the state matrix
// The method used may look complicated, but it is easy if you know the underlying theory.
// Refer the documents specified above.
void MixColumns()
{
    int i;
    uint8_t Tmp,Tm,t;
    for(i=0;i<4;i++)
    {
        t=state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ;
        Tm = state[0][i] ^ state[1][i] ; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp ;
        Tm = state[1][i] ^ state[2][i] ; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp ;
        Tm = state[2][i] ^ state[3][i] ; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp ;
        Tm = state[3][i] ^ t ; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp ;
    }
}

// Cipher is the main function that encrypts the PlainText.
void Cipher()
{
    int i,j,round=0;

    //Copy the input PlainText to state array.
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            state[j][i] = in[i*4 + j];
        }
    }

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(round=1;round<Nr;round++)
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);

    // The encryption process is over.
    // Copy the state array to output array.
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            out[i*4+j]=state[j][i];
        }
    }
}

void copyKey(uint8_t *key){
	int i;
	for(i = 0; i < Nk*4; i++){
		Key[i]=key[i];
	}

}

void copyInput(uint8_t* input, int cnt){
//	for(int i = 0; i < Nk*4; i++){
	int i;
	memset(in, 0, sizeof(uint8_t) * 16);
	for(i = 0; i < cnt; i++){
		in[i]=input[i];
	}
}

void printOutput(){
	printf("\nText after encryption:\n");
	int i;
//	for(int i = 0; i < Nk*4; i++){
	for(i = 0; i < 16; i++){
		printf("%c",out[i]);
	}
	printf("\n");
}

void copyOutToIn(){
	int i;
	for(i = 0; i < Nk*4; i++){
		in[i]=out[i];
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void InvSubBytes(){
    int i,j;
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            state[i][j] = getSBoxInvert(state[i][j]);

        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void InvShiftRows(){
    uint8_t temp;

    // Rotate first row 1 columns to right   
	temp=state[1][3];
    state[1][3]=state[1][2];
    state[1][2]=state[1][1];
    state[1][1]=state[1][0];
    state[1][0]=temp;

    // Rotate second row 2 columns to right   
	temp=state[2][0];
    state[2][0]=state[2][2];
    state[2][2]=temp;

    temp=state[2][1];
    state[2][1]=state[2][3];
    state[2][3]=temp;

    // Rotate third row 3 columns to right
    temp=state[3][0];
    state[3][0]=state[3][1];
    state[3][1]=state[3][2];
    state[3][2]=state[3][3];
    state[3][3]=temp;
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for beginners.
// Please use the references to gain more information.
void InvMixColumns(){
	int i;
    uint8_t a,b,c,d;
    for(i = 0; i < 4; i++){
		a = state[0][i];
		b = state[1][i];
		c = state[2][i];
		d = state[3][i];
		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// InvCipher is the main function that decrypts the CipherText.
void InvCipher()
{
    int i,j,round=0;

    //Copy the input CipherText to state array.
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            state[j][i] = in[i*4 + j];
        }
    }

    // Add the First round key to the state before starting the rounds.
       AddRoundKey(Nr);



            // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(round=Nr-1;round>0;round--)
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }

        // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);

    // The decryption process is over.
    // Copy the state array to output array.
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            out[i*4+j]=state[j][i];
        }
    }
}


/**
 * Encrypt a text using AES encryption in Counter mode of operation
 */
uint8_t* Cipher_CTR(uint8_t* input){//, uint8_t* output) {
	int blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
	char* str = (char*)input;
	int input_length = strlen(str);

	uint8_t* counterBlock = (uint8_t*)malloc(sizeof(uint8_t) * blockSize);

	struct timeval nonce;
	gettimeofday(&nonce, NULL);

	//Write seconds on first 4 bytes, and miliseconds on next 4
//	for(int i = 0; i < 4; ++i){
//		counterBlock[i] = (nonce.tv_sec >> i * 8) & 0xff;
//		counterBlock[i + 4] = (nonce.tv_usec >> i * 8) & 0xff;
//	}
	uint32_t* cb = (uint32_t *)counterBlock;
	cb[0] = nonce.tv_sec & 0xffffffff;
	cb[1] = nonce.tv_usec & 0xffffffff;


	copyInput(counterBlock, blockSize);
	Cipher();

	uint8_t* output = (uint8_t*)malloc((input_length + blockSize) * sizeof(uint8_t));
	memset(output, 0, sizeof(uint8_t) * blockSize);
	memcpy(output, out, sizeof(uint8_t) * blockSize);


	uint64_t blockCount = ceil((float)input_length/blockSize);

	printf("Długość ciągu wejsciowego: %lf \nLiczba blokow: %d\n", input_length, blockCount);

	uint64_t b;
	int i;

	for(b = 0; b < blockCount; ++b){
		//Write block counter as last 8 bytes
		uint64_t* cb = (uint64_t*)counterBlock;
		cb[1] = b;

		copyInput(counterBlock, blockSize);
		Cipher();

		if(b != blockCount -1){
			for(i = 0; i < blockSize; ++i){
				output[(b+1) * blockSize + i] = out[i] ^ input[b * blockSize + i];
			}
		}else{
			int blockLength = input_length % blockSize;

			for(i = 0; i < blockLength; ++i){
				output[(b+1) * blockSize + i] = out[i] ^ input[b * blockSize + i];
			}
			for(i = blockLength; i < blockSize; ++i){
				output[(b+1) * blockSize + i] = out[i] ^ 0x00;
			}
		}

	}
	return output;
}

/**
 * Decrypt a text encrypted by AES in counter mode of operation
 */
uint8_t* InvCipher_CTR(uint8_t* input){//, uint8_t* output){
	uint64_t b;
	int i;
	int blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
	char* str = (char*)input;
	int input_length = strlen(str);

	uint8_t* output = (uint8_t*)malloc((input_length - blockSize) * sizeof(uint8_t));

	uint8_t* counterBlock = (uint8_t*)malloc(sizeof(uint8_t)*16);

	copyInput(input, blockSize);
	InvCipher();

	memcpy(counterBlock, out, sizeof(uint8_t) * blockSize);


	uint64_t blockCount = ceil((float)input_length/blockSize);

	for(b = 0; b < blockCount - 1; ++b){
		//Write block counter as last 8 bytes
		uint64_t* cb = (uint64_t*)counterBlock;
		cb[1] = b;

		copyInput(counterBlock, blockSize);
		Cipher();

		for(i = 0; i < blockSize; ++i){
			output[b * blockSize + i] = out[i] ^ input[(b + 1) * blockSize + i];
		}

	}

	return output;
}
