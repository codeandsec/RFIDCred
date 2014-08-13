#include "stdafx.h"
#include <Windows.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#pragma comment(lib, "libeay32.lib")

typedef long (*fReaderOpen) (void);
typedef long (*fReaderClose) (void);
typedef long (*fLinearWrite) (PBYTE, short, short, short *, unsigned char, unsigned char);

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	int i, nrounds = 5;
	unsigned char key[32], iv[32];
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) return -1;
	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = (unsigned char *)malloc(c_len);

	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
	*len = c_len + f_len;
	return ciphertext;
}

int main(int argc, char* argv[])
{

	if (argc != 4)
	{
		printf("\nUsage: AuthGen.exe 32-bytepassword NTUsername NTPassword\n");
		printf("Example: AuthGen qIys9M9HmEywoHKy8nKAS3eq90YPt1Er Administrator MYAdminPass\n");
		return -1;
	}

	if (strlen(argv[1]) != 32)
	{
		printf("Please enter a 32-byte key string as parameter\n");
		return -1;
	}

	if (strlen(argv[2]) > 32 || strlen(argv[3]) > 64)
	{
		printf("\nMaximum username length: 32\nMaximum password length: 64\n");
		return 0;
	}

	int SecretLen = strlen(argv[2]) + strlen(argv[3]) + 1;
	char* Secret = (char*)malloc(SecretLen);
	sprintf(Secret, "%s|%s", argv[2], argv[3]);

	HMODULE hlib = LoadLibraryA("uFCoder1x.dll");
	if (hlib == NULL)
	{
		printf("Please copy uFCoder1x.dll in %PATH%\n");
		return 0;
	}

	fReaderOpen		ReaderOpen = (fReaderOpen) GetProcAddress(hlib, "ReaderOpen");
	fReaderClose	ReaderClose = (fReaderClose) GetProcAddress(hlib, "ReaderClose");
	fLinearWrite	LinearWrite = (fLinearWrite) GetProcAddress(hlib, "LinearWrite");
	if (ReaderClose == NULL || ReaderOpen == NULL || LinearWrite == NULL)
	{
		printf("Invalid DLL, please check DLL.");
		return 0;
	}

	long	retval = ReaderOpen();
	if (retval != 0)
	{
		printf("Unable to open reader");
		return 0;
	}

	DWORD		cbBlob;
	BYTE*		pbBlob;
	DWORD		dwResult;
	HCRYPTPROV	hProv;
	HCRYPTKEY	hKey;
	HCRYPTHASH	hHash = 0;
	unsigned char *key_data;
	unsigned char *ciphertext;
	int key_data_len, i;
	cbBlob = 32;
	pbBlob = (BYTE*)malloc(cbBlob + 1);
	memset(pbBlob, 0, cbBlob + 1);
	for (int i = 0; i < 32; i++)
	{
		pbBlob[i] = argv[1][i];
	}

	pbBlob[32] = 0x00;

	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = {12345, 54321};
	key_data = (unsigned char *)argv[1];
	key_data_len = strlen(argv[1]);
	if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) 
	{
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}
	
	ciphertext = aes_encrypt(&en, (unsigned char *)Secret, &SecretLen);

	char	SecretKeyFile[MAX_PATH];
	FILE*	fp;
	GetWindowsDirectory(SecretKeyFile, MAX_PATH);
	strcat(SecretKeyFile, "\\master.passwd");
	fp = fopen(SecretKeyFile, "w");
	if (!fp)
	{
		free(ciphertext);
		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);
		printf("Failed to open MyAuth file. Are you running as root?\n");
		return -1;
	}

	fwrite(ciphertext, 1, SecretLen, fp);
	fclose(fp);
	short bytesret;
	LinearWrite(pbBlob, 0, SecretLen, &bytesret, 0x60, 0);
	free(ciphertext);
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	printf("Credentials stored. Please install Credential Providerds DLL.\n");
	ReaderClose();
	return 0;
}
