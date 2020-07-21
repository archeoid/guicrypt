#include "crypt.h"
#include "util.h"
const char * modes[] = {
    "gcm",
    "ctr",
    "cfb",
    "ofb",
    "cbc",
    "ecb",
    NULL
};

const char * ret_errors[] =
{
    "OK",
    "Unknown Failure",
    "Cipher Invalid",
    "Key Size Invalid",
    "Round Number Invalid",
    "Mode Invalid",
    "IV Length is not block size",
    "tomcrypt function failed",
    "Auth Failure. Cipher text has been modified",
    "GCM can only use 16 byte block ciphers",
    "Unknown Failure"
};


static struct mode cipher_modes[7] = {{"gcm", 0, 1, 1}, {"ctr", 1, 1, 1}, {"cfb", 2, 1, 1}, {"ofb", 3, 1, 1}, {"cbc", 4, 0, 1}, {"ecb", 5, 0, 0}, {NULL, 0, 0, 0}};

void print_hash(unsigned char * hash, unsigned long len)
{
    char hex[64];
    unsigned long hex_len = 64;
    base16_encode(hash, len, hex, &hex_len, 0);
    printf("%s\n", hex);
}

int generate_iv(unsigned char ** iv, int iv_len)
{
    *iv = malloc(sizeof(char) * iv_len);
    prng(*iv, iv_len);
    return 1;
}
int do_hash(int hash_name, unsigned char * ptex, int ptex_len, unsigned char ** ctex, unsigned long * ctex_len)
{
    *ctex_len = hash_descriptor[hash_name].hashsize;
    *ctex = malloc(sizeof(char) * (*ctex_len));
    hash_memory(hash_name, ptex, ptex_len, *ctex, ctex_len);
    return 1;
}
int valid_key_size(int name, int size)
{
    if(size == cipher_descriptor[name].min_key_length ||
       size == cipher_descriptor[name].max_key_length)
        return 1;
    if(cipher_descriptor[name].min_key_length < size &&
       cipher_descriptor[name].max_key_length > size)
    {
        int new_size = size;
        cipher_descriptor[name].keysize(&new_size);
        return (size == new_size);
    }
    return 0;
}
int valid_cipher_options(int name, int key_len, int round_num)
{
    if(!valid_key_size(name, key_len))
        return -1;
    unsigned char * key = malloc(sizeof(char) * key_len);
    symmetric_key symk;
    int err = cipher_descriptor[name].setup((const unsigned char *)key, key_len, round_num, &symk);
    cipher_descriptor[name].done(&symk);
    free(key);
    if(err != CRYPT_OK) {
        return 0;
    }
    return 1;
}

int find_mode(const char * m)
{
    int idx = 0;
    while(cipher_modes[idx].name != NULL) {
        if(strcmp(cipher_modes[idx].name, m) == 0)
            return idx;
        idx++;
    }
    return -1;
}

void print_error(int r)
{
    printf("%s\n", ret_errors[MIN(r, FAILED_UNKNOWN)]);
}
int validate_parameters(struct parameters * p)
{
    int idx = find_cipher(p->cipher);
    if(idx == -1) {
        printf("Cipher, %s, does not exist\n", p->cipher);
        return FAILED_CIPHER;
    }
    int err = valid_cipher_options(idx, p->key_size, p->rounds);
    if(err == -1){
        printf("Key size, %d, is not valid\n", p->key_size);
        return FAILED_KEY_SIZE;
    }
    if(err == 0){
        printf("Number of rounds, %d, is not valid\n", p->rounds);
        return FAILED_ROUNDS;
    }
    int mode = find_mode(p->mode);
    if(mode == -1){
        printf("Mode, %s, does not exist\n", p->mode);
        return FAILED_MODE;
    }
    int block = cipher_descriptor[idx].block_length;
    p->iv_size = block;
    if(p->iv_size != block){
        printf("IV is not the same length as block, %d\n", block);
        return FAILED_IV_LEN;
    }
    p->block_size = block;
    p->cipher_idx = idx;
    p->mode_idx = mode;
    p->is_stream = cipher_modes[mode].is_stream;
    p->has_iv = cipher_modes[mode].has_iv;
    if(mode == 0 && block != 16)
        return FAILED_GCM_BLOCK;
    return OK;
}
void set_parameters(const char * cipher, const char * mode, int key_size, int rounds, struct parameters *p)
{
    p->cipher = cipher;
    p->mode = mode;
    p->key_size = key_size;
    p->rounds = rounds;
}

int prng(unsigned char * out, int out_len)
{
    static int setup = 0;
    static prng_state state;
    if(!setup)
    {
        register_prng(&fortuna_desc);
        fortuna_start(&state);
        setup = 1;
    }
    unsigned char * buffer = malloc(sizeof(char)*out_len);
    rng_get_bytes(buffer, out_len, NULL);
    fortuna_add_entropy(buffer, out_len, &state);
    free(buffer);
    fortuna_ready(&state);
    fortuna_read(out, out_len, &state);
    return OK;
}

void print_random(int size)
{
    unsigned char * buffer = malloc(sizeof(char) * size);
    prng(buffer, size);
    print_hex(buffer, size); 
}
void pad_to_block(unsigned char ** tex, unsigned long * tex_len, int block)
{
    int difference = block - ((*tex_len) % block);
    if(difference == block) {
        return;
    }
    *tex_len += difference;
    *tex = realloc(*tex, *tex_len);
    memset(*tex + *tex_len - difference, 0, difference);
}
int crypt(int encrypt, unsigned char ** tex, unsigned long * tex_len, unsigned char * key, unsigned char * IV, struct parameters * p)
{
    int r = validate_parameters(p);
    if(r)
        return r;
    if(!cipher_modes[p->mode_idx].is_stream)
        pad_to_block(tex, tex_len, p->block_size);
    switch(p->mode_idx) //cant see a better option
    {
        case 0:
            {
                if(p->block_size != 16)
                    return FAILED_GCM_BLOCK;
                
                gcm_state s;

                int err = gcm_init(&s, p->cipher_idx, key, p->key_size);
                err = gcm_add_iv(&s, IV, p->block_size);
                unsigned char *tag = calloc(sizeof(char), 64); unsigned long taglen = 16;
                if(encrypt)
                {
                    err = gcm_process(&s, *tex, *tex_len, *tex, 0);
                    err = gcm_done(&s, tag, &taglen);
                    memcpy(*tex + *tex_len, tag, taglen);
                    *tex_len += taglen;
                } else {
                    unsigned char *atag = malloc(64); unsigned long ataglen = 16;
                    int diff = (*tex_len-taglen);
                    memcpy(atag, *tex+diff, ataglen);
                    memset(*tex+diff, 0, ataglen);
                    *tex_len -= taglen;
                    if(*tex_len < 0) {
                        free(tag);
                        free(atag);
                        return FAILED_UNKNOWN;
                    }
                    err = gcm_process(&s, *tex, *tex_len, *tex, 1);
                    err = gcm_done(&s, tag, &taglen);
                    if(strcmp((char*)atag, (char*)tag) != 0){
                        free(tag);
                        free(atag);
                        return FAILED_AUTH;
                    }
                    free(atag);
                }
                free(tag);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
        case 1:
            {
                symmetric_CTR s;
                int err = ctr_start(p->cipher_idx, IV, key, p->key_size, p->rounds, CTR_COUNTER_BIG_ENDIAN, &s);
                if(encrypt)
                    err = ctr_encrypt(*tex, *tex, *tex_len, &s);
                else
                    err = ctr_decrypt(*tex, *tex, *tex_len, &s);
                err = ctr_done(&s);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
        case 2:
            {
                symmetric_CFB s;
                int err = cfb_start(p->cipher_idx, IV, key, p->key_size, p->rounds, &s);
                if(encrypt)
                    err = cfb_encrypt(*tex, *tex, *tex_len, &s);
                else
                    err = cfb_decrypt(*tex, *tex, *tex_len, &s);
                err = cfb_done(&s);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
        case 3:
            {
                symmetric_OFB s;
                int err = ofb_start(p->cipher_idx, IV, key, p->key_size, p->rounds, &s);
                if(encrypt)
                    err = ofb_encrypt(*tex, *tex, *tex_len, &s);
                else
                    err = ofb_decrypt(*tex, *tex, *tex_len, &s);
                err = ofb_done(&s);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
        case 4:
            {
                symmetric_CBC s;
                int err = cbc_start(p->cipher_idx, IV, key, p->key_size, p->rounds, &s);
                if(encrypt)
                    err = cbc_encrypt(*tex, *tex, *tex_len, &s);
                else
                    err = cbc_decrypt(*tex, *tex, *tex_len, &s);
                err = cbc_done(&s);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
        case 5:
            {
                symmetric_ECB s;
                int err = ecb_start(p->cipher_idx, key, p->key_size, p->rounds, &s);
                if(encrypt)
                    err = ecb_encrypt(*tex, *tex, *tex_len, &s);
                else
                    err = ecb_decrypt(*tex, *tex, *tex_len, &s);
                err = ecb_done(&s);
                if(err) return FAILED_TOMCRYPT;
                return OK;
            } break;
    }
    return OK;
}
void get_list(const char * src[], const char*** list, int * len)
{
    *len = 0;
    while(src[*len] != NULL)
        *len = (*len) + 1;
    
    *list = malloc(sizeof(char*) * *len);
    int i = 0;
    while(src[i] != NULL) {
        (*list)[i] = src[i];
        i++;
    }
}
void get_cipher_list(const char*** list, int * len)
{
    *len = 0;
    while(cipher_descriptor[*len].name != NULL)
        *len = (*len) + 1;
    
    *list = malloc(sizeof(char*) * *len);
    int i = 0;
    while(cipher_descriptor[i].name != NULL) {
        (*list)[i] = cipher_descriptor[i].name;
        i++;
    }
}
void get_mode_list(const char*** list, int * len)
{
    get_list(modes, list, len);
}
void get_key_ranges(int cipher, const char *** list, int * len)
{
    int min = cipher_descriptor[cipher].min_key_length;
    int max = cipher_descriptor[cipher].max_key_length;
    *list = malloc(sizeof(char*) * (max - min));
    int i = 0;
    for(int j = min; j <= max; j++)
    {
        if(valid_key_size(cipher, j))
        {
            char * str = malloc(sizeof(char) * 4);
            sprintf(str, "%d", j);
            (*list)[i] = str;
            i++;
        }
    }
    *len = i;
}
void get_round_ranges(int cipher, int key_size, const char *** list, int * len)
{
    int min = 8; //unfortunate, but no such constants exist in tomcrypt
    int max = 32;
    *list = malloc(sizeof(char*) * (max - min));
    int i = 0;
    for(int j = min; j <= max; j++)
    {
        if(valid_cipher_options(cipher, key_size, j))
        {
            char * str = malloc(sizeof(char) * 2);
            sprintf(str, "%d", j);
            (*list)[i] = str;
            i++;
        }
    }
    *len = i;
}
int get_block_size(int cipher)
{
    return cipher_descriptor[cipher].block_length;
}
void setup_crypt()
{
    register_all_ciphers();
    register_all_hashes();
}