#ifndef UTIL_H
#define UTIL_H
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
void to_base(unsigned char * data, int data_len, char * display, int * display_len, int base);

void from_base(char * display, int display_len, unsigned char * data, int * data_len, int base, int remove_newline);

int string_to_int(const char * str, int base);

int int_to_string(int i);

void append_output(unsigned char * data, int * data_len, int has_iv,  unsigned char * iv, int iv_len);

void parse_output(unsigned char * data, int data_len, unsigned char * out, unsigned long * out_len, 
                  int has_iv,  unsigned char * iv, int iv_len);


void print_hex(unsigned char* h, int len);

void print_oct(unsigned char* h, int len);

#endif