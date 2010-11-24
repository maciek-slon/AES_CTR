#include "plugin.h"

#include "md5.h"

#include <string.h>

void hash (const char * str, char * out, int size)
{
	MD5_CTX mdContext;
	unsigned int len = strlen (str);

	MD5Init (&mdContext);
	MD5Update (&mdContext, str, len);
	MD5Final (&mdContext);

	while (size > 0) {
		memcpy(out, mdContext.digest, 16);
		size -= 16;
		out += 16;
	}
}

plugin_type_t type()
{
	return PLUGIN_HASH;
}
