#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SALT 1
const char * xor_key;
int len_key;


char* encrypt(char *text, char* result) {
	if(sizeof(text) != sizeof(result)){
		return NULL;
	}
	int length = strlen(text);
    for (int i = 0; i < length; i++){
        result[i] = text[i] ^ xor_key[i % len_key] + SALT;
    }
    return result;
}

char* decrypt(char *text, char* result) {
	if(sizeof(text) != sizeof(result)){
		return NULL;
	}
	int length = strlen(text);
    for (int i = 0; i < length; i++){
        result[i] = (text[i] - SALT) ^ xor_key[i % len_key];
    }
    return result;
}




int main(){
	// // xor_key
	xor_key = "12345";
	len_key = strlen(xor_key);
	// string to encrypt.
	char *raw = "123123";
	// encrypt result.
	char *result = malloc(sizeof(raw));

	result = encrypt(raw,result);

	printf("--- raw string (ascii code): ");
	for(int i=0;i<strlen(raw);i++){
		printf("%d, ",raw[i]);
	}
	printf("\n");
	printf("encrypt_string (ascii code): ");
	for(int i=0;i<strlen(raw);i++){
		printf("%d, ",result[i]);
	}
	printf("\n");

	result = encrypt(result,result);
	printf("decrypt_string (ascii code): ");
	for(int i=0;i<strlen(raw);i++){
		printf("%d, ",result[i]);
	}
	printf("\n");
	return 0;
}


