#include <util.h>
void from_base64(char * in, int ilen_,  unsigned char * out, int * olen)
{
    int ilen = ilen_;
    static const char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    unsigned char a[4];
    unsigned char b[3];
    for(int i = 0; i < ilen + 3; i+=4)
    {
        for(int j = 0; j < 4; j++)
        {
            a[j] = i+j < ilen_ ? in[i+j] : 0;
            for(int k = 0; k < 65; k++) {
                if(base64[k] == a[j]) {
                    a[j] = k;
                    if(a[j] == 64) {
                        a[j] = 0;
                        ilen--;
                    }
                    break;
                }
            }
        }

        b[0] = (a[0] << 2) + (a[1] >> 4);
        b[1] = i+1 < ilen ? ((a[1] & 0xF) << 4) + (a[2] >> 2) : 0;
        b[2] = i+2 < ilen ? ((a[2]) << 6) + a[3] : 0;

        for(int j = 0; j < 3; j++)
            out[(i*3/4)+j] = b[j]; 
    }
    *olen = (int)(((float)ilen/4.0f)*3.0f);
}

void to_base64(unsigned char * in, int ilen, char * out, int * olen)
{
    static const char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    unsigned char a[3];
    unsigned char b[4];
    *olen = (ilen/3 + (ilen % 3 != 0)) * 4;

    for(int i = 0; i < ilen; i+=3)
    {
        for(int j = 0; j < 3; j++)
            a[j] = i+j < ilen ? in[i+j] : 0;
        
        b[0] = a[0] >> 2;
        b[1] = ((a[0] & 0x3) << 4) + (a[1] >> 4);
        b[2] = i+1 < ilen ? ((a[1] & 0xF) << 2) + (a[2] >> 6) : 64;
        b[3] = i+2 < ilen ? (a[2] & 0x3F) : 64;

        for(int j = 0; j < 4; j++)
            out[(i*4/3)+j] = base64[b[j]];
    }
    
}
void to_binary(unsigned char * in, int ilen, char * out, int * olen)
{
    *olen = ilen * 8;
    char c;
    for(int i = 0; i < ilen; i++)
    {
        c = in[i];
        for(int j = 0; j < 8; j++)
        {
            out[i*8+(7-j)] = c & 1 ? '1' : '0';
            c >>= 1;
        }
    }
}

void from_binary(char * in, int ilen, unsigned char * out, int * olen)
{
    *olen = (ilen/8 + (ilen % 8 != 0));
    for(int i = 0; i < *olen; i++)
    {
        int b = 0;
        for(int k = 0; k < 8; k++)
        {
            int l = (i)*8 + (k);
            int c = (l < ilen) ? (in[l] == '1' ? 1 : 0) : 0;
            b += c;
            b <<= 1;
        }
        b >>= 1;
        out[i] = b;
    }
}

void to_base(unsigned char * data, int data_len, char * display, int * display_len, int base)
{
    switch(base)
    {
        case 0:
            strcpy((char *)display, (const char *)data);
            *display_len = data_len;
            break;
        case 2:
            to_binary(data, data_len, display, display_len);
            break;
        case 16:
            for(int i = 0; i < data_len; i++)
                sprintf(display + i*2, "%02x", data[i]);
            *display_len = data_len*2;
            break;
        case 64:
            to_base64(data, data_len, display, display_len);
            break;
    }
}


void append_output(unsigned char * data, int * data_len, int has_iv,  unsigned char * iv, int iv_len)
{
    if(has_iv)
    {
        memmove(data + iv_len, data, *data_len);
        memcpy(data, iv, iv_len);
        *data_len += iv_len;
    }
}

void parse_output(unsigned char * data, int data_len, unsigned char * out, unsigned long * out_len, 
                  int has_iv,  unsigned char * iv, int iv_len)
{
    int len = 0;
    if(has_iv)
    {
        memcpy(iv, data, iv_len);
        len += iv_len;
    }
    memcpy(out, data+len, data_len - len);
    *out_len = data_len - len;
}

void from_base(char * display_, int display_len_, unsigned char * data, int * data_len, int base, int remove_newline)
{
    char * display = malloc(sizeof(char) * display_len_);
    memcpy(display, display_, sizeof(char) * display_len_);
    int display_len = display_len_;
    if(remove_newline)
    { 
        for(int i = 0; i < display_len; i++) //remove newlines
        {
            if(display[i] == '\n')
            {
                memmove(display + i, display + i + 1, display_len - i);
                i--;
                display_len--;
            }
        }
    }

    switch(base)
    {
        case 0:
            strcpy((char *)data, (const char *)display);
            *data_len = display_len;
            break;
        case 2:
            from_binary(display, display_len, data, data_len);
            break;
        case 16:
            for(int i = 0; i < display_len + 1; i+=2){
                int a = tolower(display[i]);
                int b = tolower(i < display_len ? display[i+1] : 0);
                
                a = (a <= 'f' && a >= 'a') ? a - 'a' + 10 : ((a <= '9' && a >= '0') ? a - '0' : 0);
                b = (b <= 'f' && b >= 'a') ? b - 'a' + 10 : ((b <= '9' && b >= '0') ? b - '0' : 0);

                data[i/2] = (a << 4) + b;
            }
            *data_len = (display_len/2 + (display_len % 2 != 0));
            break;
        case 64:
            from_base64(display, display_len, data, data_len);
            break;
    }

    free(display);
}

int string_to_int(const char * str, int base)
{
    int i = (int)strtol(str, 0, base);
    return i;
}

void print_hex(unsigned char* h, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%02x", h[i]);
    }
    printf("\n");
}

void print_oct(unsigned char* h, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%03o", h[i]);
    }
    printf("\n");
}