
#include "main.h"
#include <string.h>
#include <stdio.h>
#include <time.h>


//生成合成密钥
int generate_composite_key(unsigned char *CK, unsigned char *cnt, const unsigned char *WK) {
	unsigned char flag = 0x01;
	for (int i = 0; i <16; i++) {
		CK[i] = cnt[i] ^ WK[i];
	}
return 0;
}


int main(){

	unsigned char plaintextPtr[]={0x00,0x01,0x02,0x03,0x04,0x05,0x07,0x07};

							  
	unsigned long long p_len = sizeof(plaintextPtr);
	unsigned char cnt[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};						  
	
	//加解密密钥
	//unsigned char key[16]={0x05, 0x53, 0x69, 0x25, 0x36, 0x92, 0x52, 0x55, 0x36, 0x74, 0x34, 0x63, 0x46, 0xad, 0xf0, 0xe4};
	unsigned char c[p_len + 16];
	
	unsigned long long c_len = 0;
	unsigned char ad[0];
	unsigned long long ad_len =0;
	unsigned char c_trans[p_len + 32];

	//hash
	unsigned char hashout[p_len + 16];
	unsigned long long hashout_len = 0;
	unsigned char hashtrans[p_len + 32];

	//workingkey
	unsigned char randNum[16]={0x25, 0x69, 0x25, 0x55, 0x36, 0x74, 0x05, 0x12, 0x05, 0x12, 0x36, 0x74, 0x92, 0x52, 0x53, 0x69};
	unsigned char masterkey[16] = {0x36, 0x74, 0x34, 0x63, 0x05, 0x92, 0x52, 0x55, 0x12, 0x53, 0x69, 0x25, 0x36, 0x92, 0x52, 0x55};

	//各ECU生成工作密钥
	unsigned char workingkey[32];

	//生成合成密钥
	
	unsigned char CK[16];
	
	//计算生成工作密钥的运行时间
	unsigned char temp[32];

	clock_t wk_start, wk_finish;
	double wk_time;

	printf("WK Time:\n");
	wk_start = clock();

	for (int i = 0; i < 1000000; i++){
		for (int i = 0; i < 16; i++) {
				temp[i] = randNum[i];
			}
		for (int i = 0; i < 16; i++) {
			temp[16 + i] = masterkey[i];
		}
	crypto_hash(workingkey, temp, 32);

	}
	wk_finish = clock();
	wk_time = (double)(wk_finish - wk_start)/ CLOCKS_PER_SEC;
	printf( "%f seconds\n", wk_time);

	//生成CK时间
	clock_t ck_start, ck_finish;

	double CK_time;
	printf("CK Time:\n");
	ck_start = clock();
	unsigned char WK[16];//截取前128比特的工作密钥
	for (int i=0; i<1000000; i++){
		
		for (int i = 0;i<16; i++)
		{
			WK[i] = workingkey[i];
		}
		generate_composite_key(CK, cnt, WK);

	}
	
	ck_finish = clock();
	CK_time = (double)(ck_finish - ck_start)/ CLOCKS_PER_SEC;
	printf( "%f seconds\n", CK_time);


	//hash生成
	clock_t mac_start, mac_finish;

	double mac_time;
	printf("MAC Time:\n");
	mac_start = clock();

	for (int i = 0; i < 1000000; i++){	

		// crypto_hash(mac, hashin, p_len + 32);
		crypto_aead_encrypt(hashout,&hashout_len,plaintextPtr,p_len,ad,ad_len,cnt,CK);
		for (int i = 0; i<p_len; i++){
			hashtrans[i] = plaintextPtr[i];
		}
		for(int i = 0; i <16; i++){
			hashtrans[p_len+i] = hashout[p_len+i];
		}
		for(int i = 0; i< 16; i++){
			hashtrans[p_len+16+i] = cnt[i];
		}
	}

	
	mac_finish = clock();
	mac_time = (double)(mac_finish - mac_start)/ CLOCKS_PER_SEC;
	printf( "%f seconds\n", mac_time);

	//encryption
	clock_t enc_start, enc_finish;

	double enc_time;
	printf("Encryption Time:\n");
	enc_start = clock();
	for (int i = 0; i < 1000000; i++){

		crypto_aead_encrypt(c,&c_len,plaintextPtr,p_len,ad,ad_len,cnt,CK);

		for (int i = 0; i < c_len; i++){
				c_trans[i] = c[i];
			}
		for (int i = 0; i < 16; i++){
			c_trans[c_len+ i] = cnt[i];
		}
		
	}
	
	enc_finish = clock();
	enc_time = (double)(enc_finish - enc_start)/ CLOCKS_PER_SEC;
	printf( "%f seconds\n", enc_time );

	// //decryption
	unsigned char out[c_len-16];
	unsigned long long out_len = 0;
	unsigned char decin[c_len];


	clock_t dec_start, dec_finish;
	double dec_time;
	printf("Decryption Time:\n");

	dec_start = clock();
	for (int i = 0; i < 1000000; i++){
		for(int i = 0; i < c_len;i++){
			decin[i] = c_trans[i];
		}
	crypto_aead_decrypt(out,&out_len,decin,c_len,ad,ad_len,cnt,CK);
	}

	dec_finish = clock();
	dec_time = (double)(dec_finish - dec_start)/ CLOCKS_PER_SEC;
	printf( "%f seconds\n", dec_time);
	
	return 0;
}
