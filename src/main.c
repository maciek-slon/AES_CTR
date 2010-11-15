/*
 * main.cpp
 *
 *  Created on: 14-11-2010
 *      Author: szkudi
 */

#include "AES.h"
#include <stdio.h>

int main(){

	// Receive the length of key here.
	while(Nr!=128 && Nr!=192 && Nr!=256)
	{
		printf("Enter the length of Key(128, 192 or 256 only): ");
		scanf("%d", &Nr);
	}


	// Calculate Nk and Nr from the received value.
	Nk = Nr / 32;
	Nr = Nk + 6;
	Nb = 4;



// Part 1 is for demonstrative purpose. The key and plaintext are given in the program itself.
//     Part 1: ********************************************************

	// The array temp stores the key.
	// The array temp2 stores the plaintext.
	uint8_t temp[32] = "KacperSzkudlarek";
	uint8_t temp2[] = "To jest jakis dluzszy tekst ktory zostanie poddany szyfrowaniu AES";
	uint8_t* output;
	uint8_t* output2;

	printf("Tekst do zaszyfrowania: %s\nKlucz szyfrujący : %s\n", temp2, temp);

	copyKey(temp);
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
	KeyExpansion();

	output = Cipher_CTR(temp2);
	printf("Zakodowany ciąg: %s\n",output);


	output2 = InvCipher_CTR(output);
	printf("Odkodowny ciąg: %s", output2);


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

	return 0;
}
