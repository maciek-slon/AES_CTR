#include <stdio.h>


/*
 ** returnable errors
 **
 ** Error codes returned to the operating system.
 **
 */
#define B64_SYNTAX_ERROR        1
#define B64_FILE_ERROR          2
#define B64_FILE_IO_ERROR       3
#define B64_ERROR_OUT_CLOSE     4
#define B64_LINE_SIZE_TO_MIN    5

void b64_encode(FILE *infile, FILE *outfile, int linesize);

void b64_decode(FILE *infile, FILE *outfile);

char *b64_message(int errcode);
