/*
 * AES.h
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

#ifndef AES_CTR_H_
#define AES_CTR_H_

#define DEBUG

#include <stdint.h>
#include "matrices.h"
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>


//typedef struct _AES_data{
/*
 * Nk - Number of 32 bit words in Key;
 * Nr - Number of rounds in cypher;
 * Nb - The number of columns comprising a state in AES;
 */
int Nb, Nr, Nk;

int threads;

// in - it is the array that holds the plain text to be encrypted.
// out - it is the array that holds the output CipherText after encryption.
// state - the array that holds the intermediate results during encryption.
uint8_t in[16], out[16], state[4][4];

// The array that stores the round keys.
uint8_t RoundKey[240];

// The Key input to the AES Program
uint8_t Key[32];

uint8_t* input;
uint8_t* output;
long int in_data_size;
long int out_data_size;

//} AES_data;

void KeyExpansion();
void AddRoundKey(int round);
void SubBytes();
void ShiftRows();
void MixColumns();
void Cipher();

void InvSubBytes();
void InvShiftRows();
void InvMixColumns();
void InvCipher();

//	void Cipher_CTR(uint8_t* input, uint8_t* output);
//	void InvCipher_CTR(uint8_t* input, uint8_t* output);
void Cipher_CTR();
void InvCipher_CTR();


uint8_t getSBoxValue(int num);
uint8_t getSBoxInvert(int num);

void setNr(int Nr);
void setNk(int Nk);

void copyKey(uint8_t *key);
void copyKeyFromFile(FILE *key);
void copyInput(uint8_t* input, int cnt);

void printOutput();

void copyOutToIn();

void readInputData(FILE* in);
void writeOutputData(FILE* out);


//void KeyExpansion(AES_data* data);
//void AddRoundKey(AES_data* data, int round);
//void SubBytes(AES_data* data);
//void ShiftRows(AES_data* data);
//void MixColumns(AES_data* data);
//void Cipher(AES_data* data);
//
//void InvSubBytes(AES_data* data);
//void InvShiftRows(AES_data* data);
//void InvMixColumns(AES_data* data);
//void InvCipher(AES_data* data);
//
////	void Cipher_CTR(uint8_t* input, uint8_t* output);
////	void InvCipher_CTR(uint8_t* input, uint8_t* output);
//void Cipher_CTR(AES_data* data);
//void InvCipher_CTR(AES_data* data);
//
//
//uint8_t getSBoxValue(int num);
//uint8_t getSBoxInvert(int num);
//
//void setNr(AES_data* data, int Nr);
//void setNk(AES_data* data, int Nk);
//
//void copyKey(AES_data* data, uint8_t *key);
//void copyKeyFromFile(AES_data* data, FILE *key);
//void copyInput(AES_data* data, uint8_t* input, int cnt);
//
//void printOutput(AES_data* data);
//
//void copyOutToIn(AES_data* data);
//
//void readInputData(AES_data *data, FILE* input);
//void writeOutputData(AES_data* data, FILE* output);


#endif /* AES_CTR_H_ */







