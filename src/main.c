/*!
 * \file
 * \brief
 */

// export OMP_NUM_THREADS=N

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <omp.h>
#include <math.h>

#include "timer.h"
#include "aes.h"

/*!
 * Entry point for project.
 */
int main(int argc, char** argv)
{
	timespec_t timer;
	int key_size;
	aes_global_t data;
	volatile uint8_t c = 0xAA;
	int i;
	double t1, t2, t3;

	if (argc < 4)
	{
		printf("Usage: AES_CTR <key_length> <input_file> <output_file>");
		return (0);
	}

	key_size = atoi(argv[1]);
	if (key_size != 128 && key_size != 192 && key_size != 256)
	{
		printf("Key should be 128, 192 or 256 bit only\n");
		return (0);
	}

	timerRestart(&timer);

	aesResetGlobalData(&data);
	aesInitGlobalData(&data, key_size);
	aesPrepareCipherFromFile(&data, argv[2]);

	t1 = timerElapsedRestart(&timer);

	for (i = 0; i < 51; ++i)
		aesCipher(&data, c);

	t2 = timerElapsedRestart(&timer);

	aesStoreResult(&data, argv[3]);
	aesFreeGlobalData(&data);

	t3 = timerElapsedRestart(&timer);

	printf("Fill buffer:  %1.5lfs\n"
		"Cipher:       %1.5lfs\n"
		"Store result: %1.5lfs\n", t1, t2, t3);

	return (0);
}

