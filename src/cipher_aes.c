#include "plugin.h"

#include "aes.h"

#include <string.h>

void cipher(const char * in_fname, const char * out_fname, int key_size, const uint8_t * key) {

}

plugin_type_t type()
{
	return PLUGIN_CIPHER;
}
