#include "../src/vault.h"
#include <stdio.h>

void test_basic_vault_func(){
    vault* v = init_vault();
    print_vault(v);
    unsigned char* key = generate_key_256("aaaa", 4, NULL, key);
    if (key == NULL){
        printf("key is null");
    }
    encrypt_vault(v, key);
    print_vault(v);
    decrypt_vault(v, key);
    print_vault(v);
}

void test_file_writing_reading(){
    vault* v = init_vault();
    print_vault(v);
    unsigned char* key;
    key = generate_key_256("aaaa", 4, NULL, key);
    add_entry(v, "bob", "bob", "bob", "bob");
    encrypt_vault(v, key);
    print_vault(v);


    printf("Wrote vault file\n");
    write_vault(v, "home.vault");


    printf("Read vault file\n");
    vault* read_v = get_vault("home.vault");

    printf("Decrypted read file\n");
    decrypt_vault(read_v, key);
    print_vault(read_v);
}

void test_writing_json(){
    printf("Starting test writing json\n");
    vault* v = init_vault();
    add_entry(v, "bob@bob.com", "1245", "this is a password", "bob.com");
    print_vault(v);
    unsigned char* key;
    key = generate_key_256("aaaa", 4, NULL, key);
    encrypt_vault(v, key);
    print_vault(v);

    printf("Wrote vault file\n");
    write_vault(v, "home.vault");

    printf("Read vault file\n");
    vault* read_v = get_vault("home.vault");

    printf("Decrypted read file\n");
    decrypt_vault(read_v, key);
    print_vault(read_v);
}

void create_vault(){
    printf("Starting test writing json\n");
    vault* v = init_vault();
    print_vault(v);
    char* password = (char*)secure_malloc(100);
    secure_read(&password, "Enter vault password: ");
    unsigned char* key;
    key = generate_key_256(password, strlen(password), v->salt, key);
    encrypt_vault(v, key);
    print_vault(v);

    printf("Wrote vault file\n");
    write_vault(v, "test.vault");

    printf("Read vault file\n");
    vault* read_v = get_vault("test.vault");

    printf("Decrypted read file\n");
    decrypt_vault(read_v, key);
    print_vault(read_v);
}

int main(){
    // test_basic_vault_func();
    // printf("Done basic functionality test!");

    // printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    // test_file_writing_reading();
    // printf("Done file writing test!");

    // test_basic_vault_func();
    // test_file_writing_reading();
    create_vault();
    // test_writing_json();
    // secure_print("hello", 5);
    // char* password;
    // secure_read(&password, "enter pass: ");
    // printf("pass received: %s", password);
}
