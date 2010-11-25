#include "plugin.h"


#include <dlfcn.h>
#include <stdio.h>


int loadHashPlugin(const char * name, lib_hash_t * ret) {
	ret->handler = dlopen(name, RTLD_LAZY);
	if (!ret->handler)
	{
		fprintf(stderr, "%s\n", dlerror());
		ret->handler = NULL;
		return -1;
	}

	ret->type = dlsym(ret->handler, "type");
	if (!ret->type) {
		fprintf(stderr, "%s\n", dlerror());
		dlclose(ret->handler);
		ret->handler = NULL;
		return -1;
	}

	if (ret->type() != PLUGIN_HASH) {
		fprintf(stderr, "Library %s doesn't contain hash plugin!\n", name);
		dlclose(ret->handler);
		ret->handler = NULL;
		return -1;
	}

	ret->hash = dlsym(ret->handler, "hash");
	if (!ret->hash) {
		fprintf(stderr, "%s\n", dlerror());
		dlclose(ret->handler);
		ret->handler = NULL;
		return -1;
	}

	ret->err = dlsym(ret->handler, "err");
	if (!ret->err) {
		fprintf(stderr, "%s\n", dlerror());
		dlclose(ret->handler);
		ret->handler = NULL;
		return -1;
	}

	return 0;
}

void unloadHashPlugin(lib_hash_t * ret) {
	dlclose(ret->handler);
}
