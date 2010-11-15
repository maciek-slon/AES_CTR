/*
 * main.cpp
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

#include "AES.h"

#include <iostream>

using namespace std;

int main(int argc, char**argv){

	AES aes;

	int i;
	int Nr, Nk;

	// Receive the length of key here.
	while(Nr!=128 && Nr!=192 && Nr!=256)
	{
		cout << "Enter the length of Key(128, 192 or 256 only): ";
		cin >> Nr;
	}


	// Calculate Nk and Nr from the received value.
	Nk = Nr / 32;
	Nr = Nk + 6;

	aes.setNk(Nk);
	aes.setNr(Nr);


// Part 1 is for demonstrative purpose. The key and plaintext are given in the program itself.
//     Part 1: ********************************************************

	// The array temp stores the key.
	// The array temp2 stores the plaintext.
	//unsigned char temp[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};
	uint8_t temp[32] = "KacperSzkudlarek";
//	uint8_t temp2[16]= {0x41  ,0x42  ,0x43  ,0x44  ,0x45  ,0x46  ,0x47  ,0x48  ,0x49  ,0x4a  ,0x4b  ,0x4c  ,0x4d  ,0x4e  ,0x4f  ,0x50};
	uint8_t temp2[] = "To jest jakis dluzszy tekst ktory zostanie poddany szyfrowaniu AES";
	uint8_t* output;//[256];
	uint8_t* output2;//[256];

	cout << "Tekst do zaszyfrowania:" << endl;
	cout << temp << endl << temp2 << endl;

	aes.copyKey(temp);
//	aes.copyInput(temp2);

//           *********************************************************




// Uncomment Part 2 if you need to read Key and PlainText from the keyboard.
//     Part 2: ********************************************************
/*
	//Clear the input buffer
	flushall();

	//Recieve the Key from the user
	printf("Enter the Key in hexadecimal: ");
	for(i=0;i<Nk*4;i++)
	{
		scanf("%x",&Key[i]);
	}

	printf("Enter the PlainText in hexadecimal: ");
	for(i=0;i<Nb*4;i++)
	{
		scanf("%x",&in[i]);
	}
*/
//             ********************************************************


	// The KeyExpansion routine must be called before encryption.
	aes.KeyExpansion();

	output = aes.Cipher_CTR(temp2);
	cout << "Zakodowany ciąg: " << output << endl;
//	for(int i = 0; i < 256; ++i)
//		cout << output[i];
//	cout << endl;

	output2 = aes.InvCipher_CTR(output);
	cout << "Odkodowny ciąg: " << output2 << endl;
//	for(int i = 0; i < 66; ++i)
//		cout << output2[i];
//	cout << endl;


//	// The next function call encrypts the PlainText with the Key using AES algorithm.
//	aes.Cipher();
//
//	// Output the encrypted text.
//	aes.printOutput();
//
//	aes.copyOutToIn();
//
//    // The next function call decrypts the CipherText with the Key using AES algorithm.
//	aes.InvCipher();
//
//	aes.printOutput();
}
