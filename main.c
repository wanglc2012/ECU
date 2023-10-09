
#include "main.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

#define CRYPTO_BYTES 32
#define CRYPTO_KEYBYTES 16 //
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))
u8 constant6[63] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0c, 0x18,
		0x31, 0x22, 0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f, 0x1e, 0x3d, 0x3a,
		0x34, 0x28, 0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32, 0x24, 0x09, 0x12,
		0x25, 0x0b, 0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b, 0x36, 0x2c, 0x19,
		0x33, 0x26, 0x0d, 0x1a, 0x35, 0x2a, 0x15, 0x2b, 0x17, 0x2f, 0x1f, 0x3f,
		0x3e, 0x3c, 0x38, 0x30, 0x20 };

void load64(u64* x, u8* S) {
	int i;
	*x = 0;
	for (i = 0; i < 8; ++i)
		*x |= ((u64)S[i]) << i * 8;
}

void store64(u8* S, u64 x) {
	int i;
	for (i = 0; i < 8; ++i)
		S[i] = (u8)(x >> i * 8);
}

void permutation256(u8* S, int rounds, u8 *c) {

	int i;
	u64 x0, x1, x2, x3, x4, x5, x6, x7;
	u64 t1, t2, t3, t5, t6, t8, t9, t11;

	load64(&x0, S + 0);
	load64(&x1, S + 8);
	load64(&x2, S + 16);
	load64(&x3, S + 24);
	for (i = 0; i < rounds; ++i) {
		// addition of round constant
		x0 ^= c[i];
		// substitution layer
		sbox(x0, x1, x2, x3, x4, x5, x6, x7);
		// linear diffusion layer
		x0 = x4;
		x1 = LOTR64(x5, 1);
		x2 = LOTR64(x6, 8);
		x3 = LOTR64(x7, 25);
	}
	store64(S + 0, x0);
	store64(S + 8, x1);
	store64(S + 16, x2);
	store64(S + 24, x3);
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen, const unsigned char *npub,
	const unsigned char *k) {
	int nr0 = 52;
	int nr = 28;
	int nrf = 32;
	int b = 256, r = 64;
	u32 size = b / 8; //32
	u32 rate = r / 8; //8
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 u = adlen / rate + 1;
	u32 v = mlen / rate + 1;
	u32 vl = mlen % rate;
	u32 i, j;
	u8 A[u * rate];
	u8 M[v * rate];
	u8 S[size];
	//pad associated data
	for (i = 0; i < adlen; i++) {
		A[i] = ad[i];
	}
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; i++) {
		A[i] = 0;
	}
	//pad plaintext data
	for (i = 0; i < mlen; i++) {
		M[i] = m[i];
	}
	M[mlen] = 0x01;
	for (i = mlen + 1; i < v * rate; i++) {
		M[i] = 0;
	}

	//initalization
	for (i = 0; i < nlen; i++) {
		S[i] = npub[i];
	}
	for (i = 0; i < klen; i++) {
		S[i + nlen] = k[i];
	}
	permutation256(S, nr0, constant6);
	//processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= A[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
	}
	S[size - 1] ^= 0x80;
	// Encryption processiong plaintext data
	if (mlen != 0) {
		for (i = 0; i < v - 1; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= M[i * rate + j];
				c[i * rate + j] = S[j];
			}
			permutation256(S, nr, constant6);
		}
		for (j = 0; j <= vl; j++) {
			S[j] ^= M[(v - 1) * rate + j];
			c[(v - 1) * rate + j] = S[j];
		}
	}
	//finalization
	permutation256(S, nrf, constant6);
	//return tag
	for (i = 0; i < taglen; i++) {
		c[mlen + i] = S[i];
	}
	*clen = mlen + taglen;
	return 0;
}
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = 0;
	if (clen < CRYPTO_KEYBYTES)
		return -1;
	int nr0 = 52;
	int nr = 28;
	int nrf = 32;
	int b = 256, r = 64;
	u32 size = b / 8; //32
	u32 rate = r / 8; //8
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 u = adlen / rate + 1;
	u32 v = (clen - taglen) / rate + 1;
	u32 vl = (clen - taglen) % rate;
	u32 i, j;
	u8 A[u * rate];
	u8 M[v * rate];
	u8 S[size];
	//pad associated data
	for (i = 0; i < adlen; i++) {
		A[i] = ad[i];
	}
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; i++) {
		A[i] = 0;
	}
	//initalization
	for (i = 0; i < nlen; i++) {
		S[i] = npub[i];
	}
	for (i = 0; i < klen; i++) {
		S[i + nlen] = k[i];
	}
	permutation256(S, nr0, constant6);
	//processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= A[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
	}
	S[size - 1] ^= 0x80;
	// Encryption processiong 	ciphertext data

	if (clen != CRYPTO_KEYBYTES) {
		for (i = 0; i < v - 1; i++) {
			for (j = 0; j < rate; j++) {
				M[i * rate + j] = S[j] ^ c[i * rate + j];
				S[j] = c[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
		for (j = 0; j < vl; j++) {
			M[i * rate + j] = S[j] ^ c[i * rate + j];
			S[j] = c[i * rate + j];
		}
		S[j] ^= 0x01;
	}
	//finalization
	permutation256(S, nrf, constant6);
	// return -1 if verification fails
	for (i = 0; i < taglen; i++) {
		if (c[clen - taglen + i] != S[i]) {
			return -1;
		}
	}
	*mlen = clen - taglen;
	for (i = 0; i < clen - taglen; i++) {
		m[i] = M[i];
	}
	return 0;
}


//hash
#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))

void hash_load64(u64* x, u8* S) {
	int i;
	*x = 0;
	for (i = 0; i < 8; ++i)
		*x |= ((u64)S[i]) << i * 8;
}

void hash_store64(u8* S, u64 x) {
	int i;
	for (i = 0; i < 8; ++i)
		S[i] = (u8)(x >> i * 8);
}

void hash_permutation256(u8* S, int rounds, u8 *c) {

	int i;
	u64 x0, x1, x2, x3, x4, x5, x6, x7;
	u64 t1, t2, t3, t5, t6, t8, t9, t11;

	hash_load64(&x0, S + 0);
	hash_load64(&x1, S + 8);
	hash_load64(&x2, S + 16);
	hash_load64(&x3, S + 24);
	for (i = 0; i < rounds; ++i) {
		// addition of round constant
		x0 ^= c[i];
		// substitution layer
		sbox(x0, x1, x2, x3, x4, x5, x6, x7);
		// linear diffusion layer
		x0 = x4;
		x1 = LOTR64(x5, 1);
		x2 = LOTR64(x6, 8);
		x3 = LOTR64(x7, 25);
	}
	hash_store64(S + 0, x0);
	hash_store64(S + 8, x1);
	hash_store64(S + 16, x2);
	hash_store64(S + 24, x3);
}

u8 constant8[127] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47,
		0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16,
		0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53,
		0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07,
		0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26,
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37, 0x6f,
		0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d, 0x1a, 0x34,
		0x69, 0x52, 0x25, 0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c, 0x39,
		0x73, 0x66, 0x4c, 0x19, 0x32, 0x65, 0x4a, 0x15, 0x2a, 0x55, 0x2b, 0x57,
		0x2f, 0x5f, 0x3f, 0x7f, 0x7e, 0x7c, 0x78, 0x70, 0x60, 0x40 };

int crypto_hash(unsigned char *out, const unsigned char *in,
	unsigned long long inlen) {
	int nrh = 68;
	u32 i, j;
	int b = 256,
		r1 = 32, r2 = 128;
	u32 size = b / 8; //32    256=4*64=4*u64
	u32 rate1 = r1 / 8; //4
	u32 rate2 = r2 / 8; //128/8=16
	u64 v = inlen / rate1 + 1;
	u32 u = CRYPTO_BYTES / rate2; //32/16=2

	u8 M[v * rate1];
	u8 S[size];
	// pad in
	for (i = 0; i < inlen; ++i)
		M[i] = in[i];
	M[inlen] = 0x01;
	for (i = inlen + 1; i < v * rate1; ++i)
		M[i] = 0;
	// initialization
	for (i = 0; i < size; ++i)
		S[i] = 0;

	//absorb
	for (i = 0; i < v; ++i) {

		for (j = 0; j < rate1; ++j)
			S[j] ^= M[i * rate1 + j];

		hash_permutation256(S, nrh, constant8);
	}

	//sequeez
	for (i = 0; i < u - 1; ++i) {
		for (j = 0; j < rate2; ++j) {
			out[j + i * rate2] = S[j];
		}
		hash_permutation256(S, nrh, constant8);
	}
	for (j = 0; j < rate2; ++j) {
		out[j + i * rate2] = S[j];
	}
	return 0;
}

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