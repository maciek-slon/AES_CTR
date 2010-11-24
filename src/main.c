/*!
 * \file
 * \brief
 */

// export OMP_NUM_THREADS=N

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <string.h>


#include <omp.h>

#include "timer.h"
#include "aes.h"

#define DIR_UNKNOWN  0
#define DIR_CIPHER   1
#define DIR_DECIPHER 2


void printUsage(const char * exe) {
	printf( "USAGE:\n"
			"\t%s [options] <input_filename>\n",
			exe);
}

void printHelp(void) {
	printf("Help :-)\n");
}

/*!
 * Entry point for project.
 */
int main(int argc, char** argv)
{
	char * in_fname = NULL;
	char * out_fname = NULL;
	int rel_out_fname = 0;
	int key_size = 0;
	char * key = NULL;
	int direction = DIR_UNKNOWN;
	char * algo = NULL;
	char * generator = NULL;
	int verbose = 0;

	if (argc < 2) {
		printUsage(argv[0]);
		return EXIT_SUCCESS;
	}

	// Parsing console parameters
	int c;
	while ( (c = getopt(argc, argv, "a:cdg:hk:o:s:v")) != -1) {
		switch (c) {
		case 'a':
			algo = optarg;
			break;
		case 'c':
			if (direction == DIR_DECIPHER) {
				printf("Conflicting direction flags specified (-c and -d)!\n");
				return EXIT_FAILURE;
			} else {
				direction = DIR_CIPHER;
			}
			break;
		case 'd':
			if (direction == DIR_CIPHER) {
				printf("Conflicting direction flags specified (-c and -d)!\n");
				return EXIT_FAILURE;
			} else {
				direction = DIR_DECIPHER;
			}
			break;
		case 'g':
			generator = optarg;
			break;
		case 'h':
			printHelp();
			return EXIT_SUCCESS;
		case 'k':
			key = optarg;
			break;
		case 'o':
			if (out_fname) {
				printf("Only one -o option allowed!\n");
				return EXIT_FAILURE;
			} else {
				out_fname = optarg;
			}
			break;
		case 's':
			key_size = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			printHelp();
			return EXIT_SUCCESS;
		default:
			printf("Unknown argument: %c!\n", c);
			return EXIT_FAILURE;
			break;
		}
	}
	if (optind < argc) {
		while (optind < argc) {
			if (in_fname) {
				printf("Too many input files specified!\n");
				return EXIT_FAILURE;
			} else {
				in_fname = argv[optind];
			}

			optind++;
		}
	}


	// Checking, if all necessary parameters were set
	if (direction == DIR_UNKNOWN) {
		printf("Specify either cipher or decipher (-c/-d)!\n");
		return EXIT_FAILURE;
	}


	if (!in_fname) {
		printf("No input file specified!\n");
		return EXIT_FAILURE;
	}

	if (!out_fname) {
		rel_out_fname = 1;
		out_fname = malloc(strlen(in_fname) + 8);
		strcpy(out_fname, in_fname);
		if (direction == DIR_CIPHER)
			strcat(out_fname, ".secret");
		else if (direction == DIR_DECIPHER)
			strcat(out_fname, ".public");
	}

	if (key_size != 128 && key_size != 192 && key_size != 256) {
		printf("Key size have to be either 128, 192 or 256 bits!\n");
		return EXIT_FAILURE;
	}

	if (!algo) {
		algo = "aes";
	}

	if (!generator) {
		generator = "raw";
	}

	if (verbose) {
		printf("Input file:    %s\n", in_fname);
		printf("Output file:   %s\n", out_fname);
		printf("Key:           %s\n", key);
		printf("Key length:    %d bits\n", key_size);
		printf("Key generator: %s\n", generator);
		printf("Algorithm:     %s\n", algo);
		printf("Direction:     %s\n", direction == DIR_CIPHER ? "cipher" : "decipher");
	}

//	timespec_t timer;
//	int key_size;
//	aes_global_t data;
//	volatile uint8_t c = 0xAA;
//	int i;
//	double t1, t2, t3;

//	if (argc < 4)
//	{
//		printf("Usage: AES_CTR <key_length> <input_file> <output_file>");
//		return (0);
//	}
//
//	key_size = atoi(argv[1]);
//	if (key_size != 128 && key_size != 192 && key_size != 256)
//	{
//		printf("Key size can be 128, 192 or 256 bit only\n");
//		return (0);
//	}

//	timerRestart(&timer);

//	aesResetGlobalData(&data);
//	aesInitGlobalData(&data, key_size);
//	aesPrepareCipherFromFile(&data, argv[2]);
//
//	t1 = timerElapsedRestart(&timer);
//
//	for (i = 0; i < 51; ++i)
//		aesCipher(&data, c);
//
//	t2 = timerElapsedRestart(&timer);
//
//	aesStoreResult(&data, argv[3]);
//	aesFreeGlobalData(&data);
//
//	t3 = timerElapsedRestart(&timer);

//	printf("Fill buffer:  %1.5lfs\n"
//		"Cipher:       %1.5lfs\n"
//		"Store result: %1.5lfs\n", t1, t2, t3);

	if (rel_out_fname)
		free(out_fname);

	return 0;
}

