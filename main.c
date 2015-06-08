/*************************************************************************
    > File Name: main.c
    > Author: wayne
    > Mail: @163.com 
    > Created Time: 2015年05月27日 星期三 16时46分27秒
 ************************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "base32.h"
#include "hmac.h"
#include "sha1.h"

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



int compute_code(const uint8_t *secret, int secretLen, char *value) {
  //uint8_t val[8];
  //for (int i = 8; i--; value >>= 8) {
  //  val[i] = value;
  //}

  uint8_t hash[SHA1_DIGEST_LENGTH];
  printf("--- secret is %s\n", secret);
  printf("--- \n");
  //char val[20] = "47782269";
  //hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
  hmac_sha1(secret, secretLen, value, 8, hash, SHA1_DIGEST_LENGTH);
  memset(value, 0, sizeof(value));
  int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }
  printf("0000  is %u\n", truncatedHash);
  memset(hash, 0, sizeof(hash));
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= 1000000;
  return truncatedHash;
}


static time_t get_time(void) {
  return time(NULL);
}

static int get_timestamp(void) {
  return get_time()/30;
}

int main()
{
    const char *secret = "123";

    //uint8_t binary_secret[sizeof(secret)];
    size_t secretLen = strlen(secret);
    //size_t secretLen = base32_decode(secret, binary_secret,
    //                                        sizeof(binary_secret));
    //printf("--------- %d\n", secretLen);

    //unsigned long value = get_timestamp();
    //value = 0;
    char *value;

    value = malloc(50);
    unsigned long ul_value = get_timestamp();
    snprintf(value, 50, "%d\n", ul_value);
    printf("&&&&&%s\n", value);
    //strcpy(value, "47782269");
    //printf("%s\n", value); 
    int hs_code;

    hs_code = compute_code(secret, secretLen, value);
    free(value);
    printf("%d\n", hs_code);
    return 0;
}
