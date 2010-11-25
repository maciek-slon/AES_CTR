#include "plugin.h"

#include "b64.h"

#include <string.h>





int encode (const char * in_fname, const char * out_fname)
{
	FILE * in_f;
	FILE * out_f;

	if (!if_fname || !out_fname) {
		return B64_FILE_ERROR;
	}

	in_f = fopen(in_fname, "rb");
	if (!in_f) {
		return B64_FILE_ERROR;
	}

	out_f = fopen(out_fname, "wb");
	if (!out_f) {
		fclose(in_f);
		return B64_FILE_ERROR;
	}

	b64_encode(in_f, out_f, 72);

	fclose(in_f);
	fclose(out_f);

	return 0;
}

int decode (const char * in_fname, const char * out_fname)
{
	FILE * in_f;
	FILE * out_f;

	if (!if_fname || !out_fname) {
		return B64_FILE_ERROR;
	}

	in_f = fopen(in_fname, "rb");
	if (!in_f) {
		return B64_FILE_ERROR;
	}

	out_f = fopen(out_fname, "wb");
	if (!out_f) {
		fclose(in_f);
		return B64_FILE_ERROR;
	}

	b64_decode(in_f, out_f, 72);

	fclose(in_f);
	fclose(out_f);

	return 0;
}

plugin_type_t type()
{
	return PLUGIN_HASH;
}
