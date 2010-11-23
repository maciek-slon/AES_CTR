/*!
 * \file
 * \brief Unit testing
 */
#include "aes.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*!
 * \defgroup testing Unit testing
 * \brief Unit tests of key program functionalities
 */
/*@{*/

#if defined(NO_COLORS)
	#define WHITE_COL
	#define SUITE_COL
	#define OK_COL
	#define ERROR_COL
	#define PASSED_COL
	#define FAILED_COL
#else
	#define WHITE_COL  "\033[m"
	#define SUITE_COL  "\033[1;36m"
	#define OK_COL     "\033[32m"
	#define ERROR_COL  "\033[31m"
	#define PASSED_COL "\033[1;32m"
	#define FAILED_COL "\033[1;31m"
#endif



#define RUN_SUITE(name, func) \
			printf(SUITE_COL name "\n" WHITE_COL);\
			if (func()) {\
				printf(FAILED_COL "FAILED!\n" WHITE_COL);\
				return 1;\
			} else {\
				printf(PASSED_COL "PASSED.\n" WHITE_COL);\
				printf("-----------------------------------------------------\n");\
			}

#define RUN_TEST_5(name, func, arg1, arg2, arg3, arg4, arg5) \
			printf("\t" name);\
			if (func(arg1, arg2, arg3, arg4, arg5)) {\
				printf(ERROR_COL "ERROR!\n"WHITE_COL);\
				return 1;\
			} \
			printf(OK_COL "OK.\n"WHITE_COL);

#define RUN_TEST_3(name, func, arg1, arg2, arg3) \
			printf("\t" name);\
			if (func(arg1, arg2, arg3)) {\
				printf(ERROR_COL "ERROR!\n"WHITE_COL);\
				return 1;\
			} \
			printf(OK_COL "OK.\n"WHITE_COL);

#define RUN_TEST_2(name, func, arg1, arg2) \
			printf("\t" name);\
			if (func(arg1, arg2)) {\
				printf(ERROR_COL "ERROR!\n"WHITE_COL);\
				return 1;\
			} \
			printf(OK_COL "OK.\n"WHITE_COL);


/// Flag for switching between normal and verbose mode
int verbose;

/*!
 * Print memory content in formatted way.
 *
 * If verbose flag is not set, then this function prints nothing.
 *
 * @param ptr memory to print
 * @param size size of data to print
 * @param width length of single output row
 */
void memprint(uint8_t * ptr, int size, int width) {
	int i;

	if (!verbose)
		return;

	printf("\n");

	for (i = 0; i < size; ++i) {
		printf("%02x ", ptr[i]);
		if ( ! ((i+1) % width) )
			printf("\n");
	}
}

/*!
 * Generate round key and compare it with expected result.
 *
 * @param akey key to expand
 * @param rkey expected round key
 * @param key_size key size in bits (128, 192 or 256)
 *
 * @return 0 on success
 */
int test_key(uint8_t * akey, uint8_t * rkey, int key_size) {
	aes_global_t data;
	int result;

	aesResetGlobalData(&data);
	aesInitGlobalData(&data, key_size);
	aesKeyExpansion(&data, akey);


	result = memcmp(data.round_key, rkey, data.round_key_size);

	memprint(rkey, data.round_key_size, 16);
	memprint(data.round_key, data.round_key_size, 16);


	aesFreeGlobalData(&data);

	return result;
}

/*!
 * Test aesKeyExpansion function on some test vectors for 128, 192 and 256 bit keys.
 *
 * Test vectors were obtained from http://www.samiam.org/key-schedule.html
 *
 * @return 0 on success
 */
int test_1() {
	//
	// 128 bit keys
	//
	uint8_t akey_1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint8_t rkey_1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
						0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
						0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99,
						0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81, 0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b,
						0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90,
						0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37, 0x6a, 0xb4, 0x9b, 0xa7,
						0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b, 0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b,
						0x0e, 0xf9, 0x03, 0x33, 0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f,
						0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66, 0x49, 0x41,
						0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e };

	uint8_t akey_2[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	uint8_t rkey_2[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
						0xe8, 0xe9, 0xe9, 0xe9, 0x17, 0x16, 0x16, 0x16, 0xe8, 0xe9, 0xe9, 0xe9, 0x17, 0x16, 0x16, 0x16,
						0xad, 0xae, 0xae, 0x19, 0xba, 0xb8, 0xb8, 0x0f, 0x52, 0x51, 0x51, 0xe6, 0x45, 0x47, 0x47, 0xf0,
						0x09, 0x0e, 0x22, 0x77, 0xb3, 0xb6, 0x9a, 0x78, 0xe1, 0xe7, 0xcb, 0x9e, 0xa4, 0xa0, 0x8c, 0x6e,
						0xe1, 0x6a, 0xbd, 0x3e, 0x52, 0xdc, 0x27, 0x46, 0xb3, 0x3b, 0xec, 0xd8, 0x17, 0x9b, 0x60, 0xb6,
						0xe5, 0xba, 0xf3, 0xce, 0xb7, 0x66, 0xd4, 0x88, 0x04, 0x5d, 0x38, 0x50, 0x13, 0xc6, 0x58, 0xe6,
						0x71, 0xd0, 0x7d, 0xb3, 0xc6, 0xb6, 0xa9, 0x3b, 0xc2, 0xeb, 0x91, 0x6b, 0xd1, 0x2d, 0xc9, 0x8d,
						0xe9, 0x0d, 0x20, 0x8d, 0x2f, 0xbb, 0x89, 0xb6, 0xed, 0x50, 0x18, 0xdd, 0x3c, 0x7d, 0xd1, 0x50,
						0x96, 0x33, 0x73, 0x66, 0xb9, 0x88, 0xfa, 0xd0, 0x54, 0xd8, 0xe2, 0x0d, 0x68, 0xa5, 0x33, 0x5d,
						0x8b, 0xf0, 0x3f, 0x23, 0x32, 0x78, 0xc5, 0xf3, 0x66, 0xa0, 0x27, 0xfe, 0x0e, 0x05, 0x14, 0xa3,
						0xd6, 0x0a, 0x35, 0x88, 0xe4, 0x72, 0xf0, 0x7b, 0x82, 0xd2, 0xd7, 0x85, 0x8c, 0xd7, 0xc3, 0x26 };

	//
	// 192 bit keys
	//
	uint8_t akey_4[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint8_t rkey_4[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
						0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
						0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
						0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa,
						0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99, 0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa,
						0xc8, 0x1d, 0x19, 0xa9, 0xa1, 0x71, 0xd6, 0x53, 0x53, 0x85, 0x81, 0x60, 0x58, 0x8a, 0x2d, 0xf9,
						0xc8, 0x1d, 0x19, 0xa9, 0xa1, 0x71, 0xd6, 0x53, 0x7b, 0xeb, 0xf4, 0x9b, 0xda, 0x9a, 0x22, 0xc8,
						0x89, 0x1f, 0xa3, 0xa8, 0xd1, 0x95, 0x8e, 0x51, 0x19, 0x88, 0x97, 0xf8, 0xb8, 0xf9, 0x41, 0xab,
						0xc2, 0x68, 0x96, 0xf7, 0x18, 0xf2, 0xb4, 0x3f, 0x91, 0xed, 0x17, 0x97, 0x40, 0x78, 0x99, 0xc6,
						0x59, 0xf0, 0x0e, 0x3e, 0xe1, 0x09, 0x4f, 0x95, 0x83, 0xec, 0xbc, 0x0f, 0x9b, 0x1e, 0x08, 0x30,
						0x0a, 0xf3, 0x1f, 0xa7, 0x4a, 0x8b, 0x86, 0x61, 0x13, 0x7b, 0x88, 0x5f, 0xf2, 0x72, 0xc7, 0xca,
						0x43, 0x2a, 0xc8, 0x86, 0xd8, 0x34, 0xc0, 0xb6, 0xd2, 0xc7, 0xdf, 0x11, 0x98, 0x4c, 0x59, 0x70 };

	//
	// 256 bit keys
	//
	uint8_t akey_7[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	uint8_t rkey_7[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
						0xa5, 0x73, 0xc2, 0x9f, 0xa1, 0x76, 0xc4, 0x98, 0xa9, 0x7f, 0xce, 0x93, 0xa5, 0x72, 0xc0, 0x9c,
						0x16, 0x51, 0xa8, 0xcd, 0x02, 0x44, 0xbe, 0xda, 0x1a, 0x5d, 0xa4, 0xc1, 0x06, 0x40, 0xba, 0xde,
						0xae, 0x87, 0xdf, 0xf0, 0x0f, 0xf1, 0x1b, 0x68, 0xa6, 0x8e, 0xd5, 0xfb, 0x03, 0xfc, 0x15, 0x67,
						0x6d, 0xe1, 0xf1, 0x48, 0x6f, 0xa5, 0x4f, 0x92, 0x75, 0xf8, 0xeb, 0x53, 0x73, 0xb8, 0x51, 0x8d,
						0xc6, 0x56, 0x82, 0x7f, 0xc9, 0xa7, 0x99, 0x17, 0x6f, 0x29, 0x4c, 0xec, 0x6c, 0xd5, 0x59, 0x8b,
						0x3d, 0xe2, 0x3a, 0x75, 0x52, 0x47, 0x75, 0xe7, 0x27, 0xbf, 0x9e, 0xb4, 0x54, 0x07, 0xcf, 0x39,
						0x0b, 0xdc, 0x90, 0x5f, 0xc2, 0x7b, 0x09, 0x48, 0xad, 0x52, 0x45, 0xa4, 0xc1, 0x87, 0x1c, 0x2f,
						0x45, 0xf5, 0xa6, 0x60, 0x17, 0xb2, 0xd3, 0x87, 0x30, 0x0d, 0x4d, 0x33, 0x64, 0x0a, 0x82, 0x0a,
						0x7c, 0xcf, 0xf7, 0x1c, 0xbe, 0xb4, 0xfe, 0x54, 0x13, 0xe6, 0xbb, 0xf0, 0xd2, 0x61, 0xa7, 0xdf,
						0xf0, 0x1a, 0xfa, 0xfe, 0xe7, 0xa8, 0x29, 0x79, 0xd7, 0xa5, 0x64, 0x4a, 0xb3, 0xaf, 0xe6, 0x40,
						0x25, 0x41, 0xfe, 0x71, 0x9b, 0xf5, 0x00, 0x25, 0x88, 0x13, 0xbb, 0xd5, 0x5a, 0x72, 0x1c, 0x0a,
						0x4e, 0x5a, 0x66, 0x99, 0xa9, 0xf2, 0x4f, 0xe0, 0x7e, 0x57, 0x2b, 0xaa, 0xcd, 0xf8, 0xcd, 0xea,
						0x24, 0xfc, 0x79, 0xcc, 0xbf, 0x09, 0x79, 0xe9, 0x37, 0x1a, 0xc2, 0x3c, 0x6d, 0x68, 0xde, 0x36 };

	RUN_TEST_3("128bit::1...", test_key, akey_1, rkey_1, 128);
	RUN_TEST_3("128bit::2...", test_key, akey_2, rkey_2, 128);

	RUN_TEST_3("192bit::1...", test_key, akey_4, rkey_4, 192);

	RUN_TEST_3("256bit::1...", test_key, akey_7, rkey_7, 256);

	return 0;
}

/*!
 * Mix columns in given state and compare output with expected result.
 *
 * @param sa state to test
 * @param sg expected output
 *
 * @return 0 on success
 */
int test_mix(aes_state_t sa, aes_state_t sg) {
	aesMixColumns(&sa);
	int result = memcmp(sa.s, sg.s, 16);

	memprint(sa.s, 16, 4);
	memprint(sg.s, 16, 4);

	return result;
}

/*!
 * Test aesMixColumns function.
 *
 * @return 0 on success
 */
int test_2() {
	aes_state_t sa_1 = { {  0x01, 0xc6, 0xdb, 0xf2,
							0x01, 0xc6, 0x13, 0x0a,
							0x01, 0xc6, 0x53, 0x22,
							0x01, 0xc6, 0x45, 0x5c } };

	aes_state_t sg_1 = { {  0x01, 0xc6, 0x8e, 0x9f,
							0x01, 0xc6, 0x4d, 0xdc,
							0x01, 0xc6, 0xa1, 0x58,
							0x01, 0xc6, 0xbc, 0x9d } };

	RUN_TEST_2("1...", test_mix, sa_1, sg_1);

	return 0;
}

/*!
 * Shift rows in given state and compare output with expected result.
 *
 * @param sa state to test
 * @param sg expected output
 *
 * @return 0 on success
 */
int test_shift(aes_state_t sa, aes_state_t sg) {
	aesShiftRows(&sa);
	int result = memcmp(sa.s, sg.s, 16);

	memprint(sa.s, 16, 4);
	memprint(sg.s, 16, 4);

	return result;
}

/*!
 * Test aesShiftRows function.
 *
 * @return 0 on success
 */
int test_3() {
	aes_state_t sa_1 = { {  0x01, 0xc6, 0xdb, 0xf2,
							0x01, 0xc6, 0x13, 0x0a,
							0x01, 0xc6, 0x53, 0x22,
							0x01, 0xc6, 0x45, 0x5c } };

	aes_state_t sg_1 = { {  0x01, 0xc6, 0xdb, 0xf2,
							0xc6, 0x13, 0x0a, 0x01,
							0x53, 0x22, 0x01, 0xc6,
							0x5c, 0x01, 0xc6, 0x45} };

	RUN_TEST_2("1...", test_shift, sa_1, sg_1);

	return 0;
}

/*!
 * Cipher block of data in CTR mode and compare result with expected output.
 *
 * @param iv initialization vector (i.e. counter value)
 * @param dt data to cipher
 * @param rs expected result
 * @param key cipher key (have to be
 * @param key_size key size in bits (128, 192 or 256)
 *
 * @return 0 on success
 */
int test_ctr(uint8_t * iv, uint8_t * dt, uint8_t * rs, uint8_t * key, int key_size) {
	int result;
	uint32_t * s32;
	uint32_t * d32;
	uint32_t * r32;
	aes_global_t data;
	aes_state_t state, res, dat;

	aesResetGlobalData(&data);
	aesInitGlobalData(&data, key_size);
	aesKeyExpansion(&data, key);

	aesFillState(&state, iv);
	aesFillState(&res, rs);
	aesFillState(&dat, dt);

	memprint(state.s, 16, 16);
	aesCipherBlock(&data, &state);
	memprint(state.s, 16, 16);

	s32 = (uint32_t*)state.s;
	d32 = (uint32_t*)dat.s;
	s32[0] = d32[0] ^ s32[0];
	s32[1] = d32[1] ^ s32[1];
	s32[2] = d32[2] ^ s32[2];
	s32[3] = d32[3] ^ s32[3];

	result = memcmp(res.s, state.s, 16);

	aesFreeGlobalData(&data);

	return result;
}

/*!
 * Test aesCipherBlock function.
 *
 * Test vectors were obtained from NIST Special Publication 800-38A "Recommendation for Block Cipher Modes of Operation"
 *
 * @return 0 on success
 */
int test_5() {
	uint8_t key_1[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };

	uint8_t iv_1[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	uint8_t dt_1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t rs_1[] = {0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b };

	RUN_TEST_5("192bit::1...", test_ctr, iv_1, dt_1, rs_1, key_1, 192);

	return 0;
}

/*@}*/

/*!
 * Main function. Calls all tests.
 *
 * @param argc number of arguments passed
 * @param argv command line arguments
 *
 * @return 0 on success
 */
int main(int argc, char** argv) {
	if (argc > 1 && strcmp(argv[1], "-v") == 0)
		verbose = 1;
	else
		verbose = 0;

	RUN_SUITE("Test key schedule algorithm", test_1);
	RUN_SUITE("Test mix columns", test_2);
	RUN_SUITE("Test shift rows", test_3);

	RUN_SUITE("Test AES CTR block cipher", test_5);


	return 0;
}
