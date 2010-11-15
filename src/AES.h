/*
 * AES.h
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

#ifndef AES_CTR_H_
#define AES_CTR_H_

#include <stdint.h>


using namespace std;

class AES {
public:
	AES();
	virtual ~AES();

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
	uint8_t* Cipher_CTR(uint8_t* input);
	uint8_t* InvCipher_CTR(uint8_t* input);


	uint8_t getSBoxValue(int num);
	uint8_t getSBoxInvert(int num);

	void setNr(int Nr);
	void setNk(int Nk);

	void copyKey(uint8_t *key);
	void copyInput(uint8_t* input, int cnt = 16);

	void printOutput();



	void copyOutToIn();

private:
	/*
	 * Nk - Number of 32 bit words in Key;
	 * Nr - Number of rounds in cypher;
	 * Nb - The number of columns comprising a state in AES;
	 */
	int Nb, Nr, Nk;

	// in - it is the array that holds the plain text to be encrypted.
	// out - it is the array that holds the output CipherText after encryption.
	// state - the array that holds the intermediate results during encryption.
	uint8_t in[16], out[16], state[4][4];

	// The array that stores the round keys.
	uint8_t RoundKey[240];

	// The Key input to the AES Program
	uint8_t Key[32];

    static const uint8_t sbox[256];

    // The round constant word array, Rcon[i], contains the values given by
    // x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
    // Note that i starts at 1, not 0).
    static const uint8_t Rcon[255];

    static const uint8_t rsbox[256];

};

#endif /* AES_CTR_H_ */







