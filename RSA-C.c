#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_hex(const char* label, const unsigned char* data, int length) {
    printf("%s", label);
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n\n------------------------\n\n");
}

int hex_to_bytes(const char* hex, unsigned char* bytes, int max_len) {
    int len = strlen(hex) / 2;
    if (len > max_len) {
        fprintf(stderr, "Hex string too long\n");
        return -1;
    }
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
    return len;
}

void save_public_key_to_file(RSA* rsa, FILE* out) {
    PEM_write_RSA_PUBKEY(out, rsa);
}

void save_private_key_to_file(RSA* rsa, FILE* out) {

    PEM_write_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);
}


//RSA* load_public_key_from_file(const char* filename) {
//    FILE* file = fopen(filename, "r");
//    if (!file) {
//        perror("Failed to open file for reading public key");
//        return NULL;
//    }
//    RSA* rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
//    if (!rsa) {
//        handle_errors();
//    }
//    fclose(file);
//    printf("Public key loaded from %s\n", filename);
//    return rsa;
//}

//RSA* load_private_key_from_file(const char* filename) {
//    FILE* file = fopen(filename, "r");
//    if (!file) {
//        perror("Failed to open file for reading private key");
//        return NULL;
//    }
//    RSA* rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
//    if (!rsa) {
//        handle_errors();
//    }
//    fclose(file);
//    printf("Private key loaded from %s\n", filename);
//    return rsa;
//}
extern "C"
{
#include <openssl/applink.c>
}
int main() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        handle_errors();
    }

    // 输出公钥
    save_public_key_to_file(rsa, stdout);
    //save_private_key_to_file(rsa, stdout);
    
load:
    // 创建一个 BIO 对象，绑定到标准输入
    BIO* bio = BIO_new_fp(stdin, BIO_NOCLOSE);

    // 从 BIO 中读取公钥
    RSA* loaded_rsa_pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!loaded_rsa_pub) {
        fprintf(stderr, "Failed to read public key from stdin.\n");
        BIO_free(bio);
        goto load;
    }
start:
    unsigned char decrypted[256]; // 解密后缓冲区
    unsigned char encrypted[256]; // 密文缓冲区


    char input_content[513];
    fflush(stdin);
    fgets(input_content, 513, stdin);
    int contentlen;
    int user_encrypted_length = -1;
    int decrypted_length = -1;
    //for (contentlen = 0; input_content[contentlen] != '\0'; contentlen++);
    contentlen = strlen(input_content);
    if (contentlen == 512)
        goto de;
    else
        goto en;





de://解密
    char hex_input[513]; // 最多 256 字节的十六进制字符串
    strcpy(hex_input, input_content);           //密文输入到hex_input
    unsigned char user_encrypted[256];
    user_encrypted_length = hex_to_bytes(hex_input, user_encrypted, sizeof(user_encrypted));
    if (user_encrypted_length == -1) {
        fprintf(stderr, "Invalid hex input\n");
    }

    // 使用私钥解密
    decrypted_length = RSA_private_decrypt(user_encrypted_length,
        user_encrypted,
        decrypted,
        rsa,
        RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        handle_errors();
    }

    // 确保解密后数据是字符串
    decrypted[decrypted_length] = '\0';

    // 输出解密结果
    printf("\n\nDecrypted message:\n\n%s\n\n------------------------\n\n", decrypted);
    getchar();
    getchar();//除去缓冲区换行符
    goto start;





en://加密
    char plaintext[245]; // RSA PKCS1_PADDING 最大支持 245 字节
    if (strlen(input_content) >= 245)
    {
        printf("\n\nString too long!\n\n-------------------------\n\n");
        fflush(stdin);
        goto start;
    }
    strcpy(plaintext, input_content);   //明文输入到plaintext
    plaintext[strcspn(plaintext, "\n")] = '\0'; // 去除换行符

    // 使用导入的公钥加密
    int encrypted_length = RSA_public_encrypt(strlen(plaintext),
        (unsigned char*)plaintext,
        encrypted, loaded_rsa_pub, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        handle_errors();
    }

    // 输出密文
    print_hex("\nEncrypted message (ciphertext):\n\n", encrypted, encrypted_length);
    goto start;
}