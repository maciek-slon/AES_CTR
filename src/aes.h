/*!
 * \file
 * \brief AES functions declaration
 */
#ifndef AES_H_
#define AES_H_

#include <stdint.h>

/*!
 * Global data used by AES algorithm.
 *
 * Keeps buffer with whole file, cipher key and
 * other data necessary for proper work.
 */
typedef struct aes_global_s {
	// Data buffers
	/// Input data
	uint8_t *in_data;
	/// Size of input data
	uint32_t in_size;
	/// Size of 128-bit blocks in input data
	uint32_t in_blocks;

	// AES specific parameters
	/// Number of 32 bit words in Key;
	int Nk;
	/// Number of rounds in cypher;
	int Nr;
	/// The number of columns comprising a state in AES;
	int Nb;
	/// Size of block
	int block_size;
} aes_global_t;

/*!
 * Reset EAS global data structure.
 *
 * @param data structure to reset
 */
void aesResetGlobalData(aes_global_t * data);

/*!
 * Free all data allocated in structure.
 *
 * @param data structure to be freed
 */
void aesFreeGlobalData(aes_global_t * data);

/*!
 * Fill all fields of global AES data.
 *
 * @param data pointer to struct to be filled
 * @param in_file name of file with input data to be ciphered
 * @param key_bits number of bits in key, must be on of 128, 192 or 256
 */
void aesInitGlobalData(aes_global_t * data, const char * in_file, int key_bits);

/*!
 * Store cipher result to file.
 *
 * @param data aes global data to be stored
 * @param out_file name of output file
 */
void aesStoreResult(aes_global_t * data, const char * out_file);

/*!
 * Cipher data.
 *
 * @param data data to be ciphered
 * @param c
 */
void aesCipher(aes_global_t * data, uint32_t c);

#endif /* AES_H_ */
