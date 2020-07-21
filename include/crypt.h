#pragma once
#include <tomcrypt.h>
#include <math.h>

struct parameters {
    const char * cipher, * mode;
    int key_size, iv_size, rounds, cipher_idx, mode_idx, block_size;
    int is_stream, has_iv;
};
struct mode {
    char * name;
    int idx;
    int is_stream;
    int has_iv;
};

enum returns
{
    OK = 0,
    FAILED = 1,
    FAILED_CIPHER = 2,
    FAILED_KEY_SIZE = 3,
    FAILED_ROUNDS = 4,
    FAILED_MODE = 5,
    FAILED_IV_LEN = 6,
    FAILED_TOMCRYPT = 7,
    FAILED_AUTH = 8,
    FAILED_GCM_BLOCK = 9,
    FAILED_UNKNOWN = 10
};

void setup_crypt(void);

void get_hash(int idx, unsigned char * ptex, unsigned long ptex_len, unsigned char * otex, unsigned long * otex_len);

void print_error(int r);

void print_hash(unsigned char * hash, unsigned long len);

int crypt(int encrypt, unsigned char ** tex, unsigned long * tex_len, unsigned char * key, unsigned char * IV, struct parameters * p);

void print_hex(unsigned char* h, int len);

void print_oct(unsigned char* h, int len);

int generate_iv(unsigned char ** iv, int iv_len);

int do_hash(int hash_name, unsigned char * ptex, int ptex_len, unsigned char ** ctex, unsigned long * ctex_len);

int valid_key_size(int name, int size);

int valid_cipher_options(int name, int key_len, int round_num);

int validate_parameters(struct parameters * p);

void set_parameters(const char * cipher, const char * mode, int key_size,int rounds, struct parameters *p);

int find_mode(const char * m);

int prng(unsigned char * out, int out_len);

void print_random(int size);

void get_cipher_list(const char*** list, int * len);

void get_mode_list(const char*** list, int * len);

void get_key_ranges(int cipher, const char *** list, int * len);

int get_block_size(int cipher);

void get_round_ranges(int cipher, int key_size, const char *** list, int * len);

void test();