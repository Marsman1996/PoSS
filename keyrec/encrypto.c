#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SALT 1
const char * xor_key;
int len_key;


char* encrypt(char *text, char* result, int length) {
	if(sizeof(text) != sizeof(result)){
		return NULL;
	}
    for (int i = 0; i < length; i++){
        result[i] = text[i] ^ xor_key[i % len_key] + SALT;
    }
    return result;
}


int main(){
	// // xor_key
	xor_key = "4@!32^*125";
	len_key = strlen(xor_key);
	// string to encrypt.
	char *raw = (char []){67, 58, 92, 80, 114, 111, 103, 114, 97, 109, 32, 70, 105, 108, 101, 115, 92, 86, 77, 119, 97, 114, 101, 92, 86, 77, 119, 97, 114, 101, 32, 84, 111, 111, 108, 115, 92, };
	// plain text is C:\Program Files\VMware\VMware Tools\
	// encrypt text is: {118, 123, 126, 100, 65, 48, 76, 64, 82, 91, 21, 7, 75, 88, 86, 44, 119, 100, 126, 65, 84, 51, 71, 104, 101, 18, 92, 83, 65, 83, 21, 21, 77, 91, 95, 44, 119, 77, }
	int length = strlen(raw);
	char *result = malloc(sizeof(char)*length);
	result = encrypt(raw,result,length);

	printf("raw: {");
	for(int i=0;i<length;i++){
		printf("%d, ",raw[i]);
	}
	printf("}\n\n");
	printf("enc: {");
	for(int i=0;i<length;i++){
		printf("%d, ",result[i]);
	}
	printf("}\n\n");

	char *result2 = malloc(sizeof(char)*length);
	result2 = encrypt(result,result2,length);
	printf("dec: {");
	for(int i=0;i<length;i++){
		printf("%d, ",result2[i]);
	}
	printf("}\n");
	printf("\nThe decrypt str is: %s\n", result2);
	free(result2);
	free(result);
	return 0;
}



