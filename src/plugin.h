#ifndef PLUGIN_H_
#define PLUGIN_H_

#include <stdint.h>

typedef unsigned int plugin_type_t;

#define PLUGIN_OTHER  0x0000
#define PLUGIN_HASH   0x0001
#define PLUGIN_CIPHER 0x0002
#define PLUGIN_CODE   0x0003

typedef int (*hash_func_t) (const char *, char *, int);
typedef int (*cipher_func_t) (const char *, const char *, int, const uint8_t *);
typedef int (*code_func_t) (const char *, const char *);

typedef int (*type_func_t) (void);
typedef char * (*err_func_t) (int);

typedef struct {
	void * handler;
	hash_func_t hash;
	type_func_t type;
	err_func_t err;
} lib_hash_t;

typedef struct {
	void * handler;
	cipher_func_t cipher;
	cipher_func_t decipher;
	type_func_t type;
} lib_cipher_t;

typedef struct {
	void * handler;
	code_func_t cipher;
	code_func_t decipher;
	type_func_t type;
} lib_code_t;


int loadHashPlugin(const char * name, lib_hash_t * ret);
void unloadHashPlugin(lib_hash_t * ret);

#endif /* PLUGIN_H_ */
