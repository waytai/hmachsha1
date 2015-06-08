/*************************************************************************
    > File Name: hmac_test.c
    > Author: wayne
    > Mail: @163.com 
    > Created Time: 2015年06月05日 星期五 10时16分00秒
 ************************************************************************/
#include <assert.h>
#include<stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "base32.h"
#include "hmac.h"
#include "sha1.h"
#include "b64.c"
#include "b64.h"

static const char hex_table_uc[16] = { '0', '1', '2', '3',  
                                       '4', '5', '6', '7',  
                                       '8', '9', 'A', 'B',  
                                       'C', 'D', 'E', 'F' };  
static const char hex_table_lc[16] = { '0', '1', '2', '3',  
                                       '4', '5', '6', '7',  
                                       '8', '9', 'a', 'b',  
                                       'c', 'd', 'e', 'f' };  

char *encodeToHex(char *buff, const uint8_t *src, int len, int type) {  
    int i;  
  
    const char *hex_table = type ? hex_table_lc : hex_table_uc;  
  
    for(i = 0; i < len; i++) {  
        buff[i * 2]     = hex_table[src[i] >> 4];  
        buff[i * 2 + 1] = hex_table[src[i] & 0xF];  
    }  
  
    buff[2 * len] = '\0';  
     
    return buff;  
}

int main()
{
uint8_t thmac[40];
hmac_sha1((uint8_t *)"123", 3,
            (uint8_t *)"47782269", 8,
            thmac, sizeof(thmac));
printf("%s\n", thmac);
printf("%d\n", strlen(thmac));

    //printf("%s\n", thmac);
char *encode_out;
encode_out = malloc(256);
char *buff;
buff = malloc(256);

encode_out = encodeToHex(buff, thmac, strlen(thmac), 1);
printf("------%s\n", encode_out);
free(encode_out);

//char out_base64[256] = {0};
//int len_out_base64 = sizeof(out_base64);
//b64_encode(out, strlen(out), out_base64, &len_out_base64);
//printf("b64_enc: %s\n", out_base64);


//char out_base64[256] = {0};
//int len_out_base64 = sizeof(out_base64);
//printf("%d\n", len_out_base64);
//b64_encode(thmac, strlen(thmac), out_base64, &len_out_base64);
//printf("b64_enc: %s\n", out_base64);
return 0;
}

