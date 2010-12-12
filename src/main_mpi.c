/* This program sums all rows in an array using MPI parallelism.
 * The root process acts as a master and sends a portion of the
 * array to each child process. Master and child processes then
 * all calculate a partial sum of the portion of the array assigned
 * to them, and the child processes send their partial sums to
 * the master, who calculates a grand total.
 */

#include <mpi.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <string.h>


#include "plugin.h"
#include "aes.h"

#define DIR_UNKNOWN  0
#define DIR_CIPHER   1
#define DIR_DECIPHER 2

void memprint(uint8_t * ptr, int size, int width) {
	int i;

	for (i = 0; i < size; ++i) {
		printf("%02x ", ptr[i]);
		if ( ! ((i+1) % width) )
			printf("\n");
	}
}

int main(int argc, char **argv)
{
	// variables necessary for MPI
    int my_id, root, ierr, num_procs;

    // variables used for storing cipher settings
	char * in_fname = NULL;
	char * out_fname = NULL;
	int rel_out_fname = 0;
	int key_size = 0;
	char * key = NULL;
	int direction = DIR_UNKNOWN;
	char * algo = NULL;
	char * generator = NULL;
	int verbose = 0;
	int failure = 0;
	uint8_t genkey[32];

	uint8_t * input_buffer;

	void * buffer;


	aes_global_t data;

	lib_hash_t lib_hash;

	int failed = 1;

	aes_times_t times;
	double ela;

    /*
     * Now replicate this process to create parallel processes.
     * From this point on, every process executes a separate copy
     * of this program
     */
    ierr = MPI_Init(&argc, &argv);

    if (ierr != MPI_SUCCESS) {
    	fprintf(stderr, "OpenMPI initialization failed.\n");
    	return -1;
    }

    // set root process number
    root = 0;


    /* find out MY process ID, and how many processes were started. */
    ierr = MPI_Comm_rank(MPI_COMM_WORLD, &my_id);
    ierr = MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

    if (my_id == root) {
    	//printf("Spawned %d processes.\n", num_procs);
    	//fflush(stdout);

    	if (argc < 2) {
    		//printUsage(argv[0]);

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
    				failed = 2;
    				break;
    			} else {
    				direction = DIR_CIPHER;
    			}
    			break;
    		case 'd':
    			if (direction == DIR_CIPHER) {
    				printf("Conflicting direction flags specified (-c and -d)!\n");
    				failed = 2;
    				break;
    			} else {
    				direction = DIR_DECIPHER;
    			}
    			break;
    		case 'g':
    			generator = optarg;
    			break;
    		case 'h':
    			//printHelp();
    			failed = 2;
    			break;
    		case 'k':
    			key = optarg;
    			break;
    		case 'o':
    			if (out_fname) {
    				printf("Only one -o option allowed!\n");
    				failed = 2;
    				break;
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
    			//printHelp();
    			failed = 2;
    			break;
    		default:
    			printf("Unknown argument: %c!\n", c);
    			failed = 2;
    			break;
    		}

    		if (failed == 2)
    			break;
    	}

    	if ( (optind < argc) && (failed < 2) ) {
    		while (optind < argc) {
    			if (in_fname) {
    				printf("Too many input files specified!\n");
    				break;
    			} else {
    				in_fname = argv[optind];
    			}

    			optind++;
    		}
    	}

    	if (failed == 2) {
    		printf("failed.\n");
    		fflush(stdout);
    	}


    	// Checking, if all necessary parameters were set
    	if (direction == DIR_UNKNOWN && failed < 2) {
    		printf("Specify either cipher or decipher (-c/-d)!\n");
    		failed = 2;
    	}


    	if (!in_fname && failed < 2) {
    		printf("No input file specified!\n");
    		failed = 2;
    	}

    	if (!out_fname  && failed < 2) {
    		rel_out_fname = 1;
    		out_fname = malloc(strlen(in_fname) + 8);
    		strcpy(out_fname, in_fname);
    		if (direction == DIR_CIPHER)
    			strcat(out_fname, ".secret");
    		else if (direction == DIR_DECIPHER)
    			strcat(out_fname, ".public");
    	}

    	if (key_size != 128 && key_size != 192 && key_size != 256  && failed < 2) {
    		printf("Key size have to be either 128, 192 or 256 bits!\n");
    		failed = 2;
    	}

    	if (!key  && failed < 2) {
    		printf("Key not specified!\n");
    		failed = 2;
    	}

    	if (!algo) {
    		algo = "aes";
    	}

    	if (!generator) {
    		generator = "raw";
    	}


    	if (verbose  && failed < 2) {
    		printf("Input file:    %s\n", in_fname);
    		printf("Output file:   %s\n", out_fname);
    		printf("Key:           %s\n", key);
    		printf("Key length:    %d bits\n", key_size);
    		printf("Key generator: %s\n", generator);
    		printf("Algorithm:     %s\n", algo);
    		printf("Direction:     %s\n", direction == DIR_CIPHER ? "cipher" : "decipher");
    	}

    	// find all required plugins
		if (failed < 2 && loadHashPlugin(generator, &lib_hash) != 0) {
			printf("Unable to load key generator plugin.\n");
			failure = 1;
		}

		// prepare key from given input
		lib_hash.hash(key, genkey, key_size / 8);

		if (failed < 2 && verbose) {
				printf("Key:           ");
				memprint(genkey, key_size / 8, key_size / 8);
		}


		// load data from file, compute all necessary parameters
		if(failed < 2)
		{
			FILE * in_f;
			int per_proc;
			int rest;

			aesInitGlobalData(&data, key_size);


			in_f = fopen(in_fname, "rb");

			if (in_f == NULL)
				perror("Can't open input file!");

			// get input file size
			fseek(in_f, 0, SEEK_END);
			data.in_size = ftell(in_f);
			if (direction == DIR_DECIPHER)
				data.in_size -= 8;
			data.in_blocks = (uint32_t) ceil(1.0 * data.in_size / data.block_size);
			data.in_blocks = (uint32_t) ceil(1.0 * data.in_blocks / num_procs) * num_procs;

			fseek(in_f, 0, SEEK_SET);

			per_proc = data.in_blocks / num_procs;
			rest = data.in_blocks % num_procs;


			//printf("Input file has %d bytes, which is %d blocks.\n", data.in_size, data.in_blocks);
			//printf("Each of %d processes will have %d blocks in buffer (%d blocks left).\n", num_procs, per_proc, rest);

			data.in_blocks /= num_procs;

			// allocate memory for input buffer
			input_buffer = (uint8_t *) malloc(data.in_blocks * data.block_size * num_procs);
			if (input_buffer == NULL)
			{
				fclose(in_f);
				perror("Can't allocate memory for input buffer!");
			}

			if (direction == DIR_CIPHER) {
				data.nonce_0 = time(NULL);
				data.nonce_1 = 1;
			} else {
				fread(&(data.nonce_0), sizeof(uint32_t), 1, in_f);
				fread(&(data.nonce_1), sizeof(uint32_t), 1, in_f);
			}

			// load file content into buffer
			if (data.in_size != fread(input_buffer, sizeof(uint8_t), data.in_size, in_f))
			{
				free(input_buffer);
				fclose(in_f);
				perror("Can't read input file to buffer!");
			}

			fclose(in_f);

			failed = 0;
		}


    }
    // end of data preparation


// ---------------------------------------------------------------------------------
// WARNING! MAGIC SECTION BEGINS HERE!!
// ---------------------------------------------------------------------------------
    if (my_id == root) {
    	clock_gettime(CLOCK_REALTIME, &(times.t0));
    }

    // broadcast global data to all processes
    MPI_Bcast(&key_size, 1, MPI_INT, root, MPI_COMM_WORLD);
    MPI_Bcast(&direction, 1, MPI_INT, root, MPI_COMM_WORLD);
    MPI_Bcast(genkey, key_size/8, MPI_BYTE, root, MPI_COMM_WORLD);
    MPI_Bcast(&data.in_blocks, 4, MPI_BYTE, root, MPI_COMM_WORLD);
    MPI_Bcast(&data.nonce_0, 4, MPI_BYTE, root, MPI_COMM_WORLD);
    MPI_Bcast(&data.nonce_1, 4, MPI_BYTE, root, MPI_COMM_WORLD);

	aesInitGlobalData(&data, key_size);

    // allocate data buffer for each process
	//buffer = malloc(data.in_blocks * data.block_size);
	//MPI_Buffer_attach (buffer, data.in_blocks * data.block_size);

    data.in_data = malloc(data.in_blocks * data.block_size);
    aesKeyExpansion(&data, genkey);

    // scatter data to all processes
	MPI_Scatter(input_buffer, data.in_blocks*data.block_size, MPI_BYTE, data.in_data,  data.in_blocks*data.block_size, MPI_BYTE, root, MPI_COMM_WORLD);

	if (my_id == root) {
		clock_gettime(CLOCK_REALTIME, &(times.t1));
	}

	// process data - cipher/decipher given block
	aesCipherT(&data);

	if (my_id == root) {
		clock_gettime(CLOCK_REALTIME, &(times.t2));
	}

	// return processed data
	MPI_Gather(data.in_data, data.in_blocks*data.block_size, MPI_BYTE, input_buffer,  data.in_blocks*data.block_size, MPI_BYTE, root, MPI_COMM_WORLD);

	if (my_id == root) {
		clock_gettime(CLOCK_REALTIME, &(times.t3));
		aesPrintTimes(times);
	}

// ---------------------------------------------------------------------------------
// NOTE: Chill out, all the magic is gone now.
// ---------------------------------------------------------------------------------




	// store processed file
	if (my_id == root) {
		{
			FILE * out_f;

			out_f = fopen(out_fname, "wb");

			if (out_f == NULL)
				printf("Can't open output file!\n");

			if (direction == DIR_CIPHER) {
				fwrite(&(data.nonce_0), sizeof(uint32_t), 1, out_f);
				fwrite(&(data.nonce_1), sizeof(uint32_t), 1, out_f);
			}

			// write output buffer into file
			if (data.in_size != fwrite(input_buffer, sizeof(uint8_t), data.in_size, out_f))
			{
				fclose(out_f);
				perror("Can't store output file!");
			}

			fclose(out_f);
		}


		free(input_buffer);

		unloadHashPlugin(&lib_hash);
	}

	free(data.in_data);

    ierr = MPI_Finalize();

    return 0;
}
