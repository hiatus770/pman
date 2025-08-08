#pragma once

#include <openssl/core_dispatch.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>
#include <termios.h>
#include "utils.h"

#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define SALT_SIZE 32
#define IV_SIZE 16


typedef enum {
    ENCRYPTED,
    DECRYPTED,
    ERROR
} vault_state;

typedef enum {
    EMAIL = 0,
    PASSWORD = 1,
    URL = 2,
    NOTES = 3
} entry_field;

char* entry_field_string[] = {"email", "password", "url", "notes"};

typedef struct {
    unsigned char* data;
    unsigned char salt[32]; // This is the first 32 bytes of the file
    unsigned char iv[16];   // This is the 16 bytes after the first 32 bytes, both are unencrypted
    size_t data_length; // This will change when we write to the file or modify the cjson stuff
    vault_state state;
} vault;


void* secure_malloc(size_t size){
    void* secure_ptr;

    if (size <= 0){
        printf("ERROR: tried to allocate size <= 0, returning NULL");
        return NULL;
    }

    size_t alloc_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    secure_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (secure_ptr == MAP_FAILED){
        printf("Failed to map\n");
        return NULL;
    }

    if (mlock(secure_ptr, alloc_size) != 0){
        printf("Failed to lock\n");
        munmap(secure_ptr, alloc_size);
        return NULL;
    }

    return secure_ptr;
}

void secure_free(void* addr, size_t size){
    if (!addr || addr == NULL){
        printf("Cannot free null/empty address");
        return;
    }

    size_t alloc_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    memset(addr, 0, alloc_size);
    munlock(addr, alloc_size);
    munmap(addr, alloc_size);
}

void secure_print(const unsigned char *data, size_t len){
    ssize_t ret = write(STDOUT_FILENO, data, len);
    if (ret < 0){
        printf("Failed to write to output");
    }
}

void secure_read(char** out, char* message){
    printf("%s", message);
    struct termios term;
    tcgetattr(fileno(stdin), &term);

    term.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), 0, &term);

    char* password = (char*)secure_malloc(200);
    fgets(password, 200, stdin);

    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &term);
    *out = password;
}


unsigned char* generate_key_256(char* password, int p_length, unsigned char* salt, unsigned char* key){
    int key_len = 32;

    key = (unsigned char*)secure_malloc(key_len);
    // Assume the key has already been allocated with a length of 256 bits
    PKCS5_PBKDF2_HMAC(password, p_length, salt, SALT_SIZE, 100000, EVP_sha256(), key_len, key);

    return key;
}

void print_vault(vault* v){
    printf("Salt: ");
    print_bytes(v->salt, SALT_SIZE);
    printf("IV: ");
    print_bytes(v->iv, IV_SIZE);
    printf("Data: %s\n", v->data);

    if (v->state == DECRYPTED){
        printf("Status: Decrypted\n");
    } else {
        printf("Status: Encrypted\n");
    }
}

vault* get_vault(char* directory){
    vault* v = (vault*)secure_malloc(sizeof(vault));
    v->state = ENCRYPTED;

    // This will decrypt based on the file directory passed, should be a relative or full path
    printf("Opening vault %s\n", directory);
    FILE *fptr;
    fptr = fopen(directory, "rb");

    if (!fptr){
        printf("Error opening file");
        return NULL;
    }

    if (fseek(fptr, 0, SEEK_END) != 0){
        printf("Fseek failed");
        fclose(fptr);
        return NULL;
    }

    long file_size = ftell(fptr);
    printf("File size from ftell: %ld\n", file_size);

    if (file_size == -1L){
        printf("ftell failed");
        fclose(fptr);
        return NULL;
    }

    v->data = (unsigned char*)secure_malloc(file_size - SALT_SIZE - IV_SIZE);

    if (!v->data){
        printf("Memory allocation failed");
        fclose(fptr);
        return NULL;
    }

    if (fseek(fptr, 0, SEEK_SET) != 0){
        printf("seek set failed");
    }

    printf("Reading salt at %ld\n", ftell(fptr));
    fread(v->salt, 1, 32, fptr); // Read the salt
    printf("Reading iv at %ld\n", ftell(fptr));
    fread(v->iv, 1, 16, fptr); // Read the initialization vector

    if (fseek(fptr, SALT_SIZE + IV_SIZE, SEEK_SET) != 0){
        printf("seek set failed");
    }

    size_t bytes_read = fread(v->data, 1, file_size, fptr);
    v->data_length = bytes_read;
    printf("Raw bytes %d: ", bytes_read);
    for (size_t i = 0; i < bytes_read; i++){
        printf("%02X ", v->data[i]); // Print out each of the bytes
    }
    printf("\n");

    printf("Salt: ");
    for(size_t i = 0; i < SALT_SIZE; i++){
        printf("%02X ", v->salt[i]);
    }
    printf("\n");

    printf("IV: ");
    for(size_t i = 0; i < IV_SIZE; i++){
        printf("%02X ", v->iv[i]);
    }
    printf("\n");

    return v;
}

/**
 * This write the vault to a file of choice
 * WARNING: Will write either encrypted or unencrypted vault to the file
 */
void write_vault(vault* v, char* directory){
    FILE *fptr;
    fptr = fopen(directory, "w");

    if (v->state == DECRYPTED){
        printf("Error: Cannot write a decrypted vault\n");
        return;
    }

    if (!fptr){
        printf("Could not find file %s", directory);
        return;
    }

    fwrite(v->salt, sizeof(unsigned char), SALT_SIZE, fptr);

    if (fseek(fptr, SALT_SIZE, SEEK_SET) != 0){
        printf("Failed to use fseek\n");
        return;
    }

    fwrite(v->iv, sizeof(unsigned char), IV_SIZE, fptr);

    if (fseek(fptr, IV_SIZE + SALT_SIZE, SEEK_SET) != 0){
        printf("Failed to use fseek\n");
    }

    printf("Wrote %d bytes to %s\n\n", v->data_length, directory);
    fwrite(v->data, sizeof(unsigned char), v->data_length, fptr);
    fclose(fptr);

}

void add_entry(vault* v, char* email, char* password, char* notes, char* url){
    if (v->state == ENCRYPTED){
        printf("Not decrypted, not possible!\n");
        return;
    } else {
        printf("Adding entry to file\n");
    }

    // Initialize the json from the string
    const char *parse_end = NULL;
    cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
    if (!json_array){
        printf("Error parsing JSON data from the vault with length opts!\n");
        return;
    } else {
        printf("Successfullly parsed json data\n");
    }

    printf("Freeing %d\n", v->data_length);

    secure_free(v->data, v->data_length);

    cJSON *new_entry = cJSON_CreateObject();
    cJSON_AddStringToObject(new_entry, entry_field_string[EMAIL], email);
    cJSON_AddStringToObject(new_entry, entry_field_string[PASSWORD], password);
    cJSON_AddStringToObject(new_entry, entry_field_string[NOTES], notes);
    cJSON_AddStringToObject(new_entry, entry_field_string[URL], url);

    cJSON_AddItemToArray(json_array, new_entry);
    char *updated_data = cJSON_PrintUnformatted(json_array);
    v->data_length = strlen(updated_data);
    v->data = (unsigned char*)secure_malloc(v->data_length);
    memcpy(v->data, updated_data, v->data_length);

    // Clean up
    // free(updated_data);
    cJSON_Delete(json_array);

    printf("Added entry to vault\n");
}

// This will be used to add extra passwords, add extra stuff here too
void modify_entry(vault* v, int ind, char* entry, char* new_val){

}

void encrypt_vault(vault* v, unsigned char* key) {
    if (v->state == ENCRYPTED) {
        printf("Cannot encrypt encrypted vault");
        return;
    }

    EVP_CIPHER_CTX* encrypt = EVP_CIPHER_CTX_new();
    if (!encrypt) {
        printf("Failed to create encryption context\n");
        return;
    }


    if (!EVP_EncryptInit_ex(encrypt, EVP_aes_256_gcm(), NULL, key, v->iv)) {
        printf("EncryptInit failed\n");
        EVP_CIPHER_CTX_free(encrypt);
        return;
    }


    int data_len = strlen((char*)v->data);  // Ensure that v->data is a proper null-terminated string
    int update_len = 0, final_len = 0;
    int buffer_size = data_len + AES_BLOCK_SIZE;

    // Allocate your output buffer
    unsigned char* cipher_text = (unsigned char*)secure_malloc(buffer_size);
    if (!cipher_text) {
        printf("Failed to allocate cipher_text\n");
        EVP_CIPHER_CTX_free(encrypt);
        return;
    }

    // Encrypt update phase
    if (!EVP_EncryptUpdate(encrypt, cipher_text, &update_len, v->data, v->data_length)) {
        printf("EncryptUpdate failed\n");
        secure_free(cipher_text, buffer_size);
        EVP_CIPHER_CTX_free(encrypt);
        return;
    }

    // Encrypt final phase: note the output goes to cipher_text + update_len
    if (!EVP_EncryptFinal_ex(encrypt, cipher_text + update_len, &final_len)) {
        printf("EncryptFinal_ex failed\n");
        secure_free(cipher_text, buffer_size);
        EVP_CIPHER_CTX_free(encrypt);
        return;
    }

    int total_ciphertext_len = update_len + final_len;
    printf("Total ciphertext length: %d\n", total_ciphertext_len);

    // Free original data memory then set new cipher_text as v->data
    secure_free(v->data, v->data_length);
    v->data = cipher_text;
    v->data_length = total_ciphertext_len;
    v->state = ENCRYPTED;

    EVP_CIPHER_CTX_free(encrypt);
}


/**
 * Initialize the vault with an unencrypted state and an empty json string []
 */
vault* init_vault(){
    vault* v = (vault*)secure_malloc(sizeof(vault));
    v->state = DECRYPTED;
    // This creates the salt, iv, and uses the master password to encrypt for the first time
    RAND_bytes(v->salt, 32);
    RAND_bytes(v->iv, 16);

    // Now we are going to init the stuff with random data
    cJSON *json_array = cJSON_CreateArray();
    if (!json_array){printf("Error creating json array\n"); return NULL;};

    char *tmp = cJSON_PrintUnformatted(json_array);
    int len = strlen(tmp);

    v->data = (unsigned char*)secure_malloc(len + 1);
    memcpy(v->data, tmp, len + 1);
    v->data_length = len;
    free(tmp); // free the originally allocated memory


    return v;
}

void decrypt_vault(vault* v, unsigned char* key){
    // What this will do is change the unsigned char data
    if (v->state == DECRYPTED){
        printf("Cannot decrypt decrypted vault");
        return;
    }
    v->state = DECRYPTED;

    int p_len = v->data_length;
    int f_len = 0;
    unsigned char *plaintext = (unsigned char*)secure_malloc(v->data_length);

    EVP_CIPHER_CTX* decrypt = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(decrypt);

    EVP_DecryptInit_ex(decrypt, EVP_aes_256_gcm(), NULL, key, v->iv);
    EVP_DecryptUpdate(decrypt, plaintext, &p_len, v->data, v->data_length);
    EVP_DecryptFinal_ex(decrypt, plaintext + p_len, &f_len);

    v->data = plaintext;
    v->data_length = p_len + f_len;
}
