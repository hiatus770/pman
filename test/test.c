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

void test_pipe_json(){
    printf("Starting test: pipe JSON to Vim\n");
    vault* v = init_vault();
    add_entry(v, "bob@bob.com", "1245", "this is a password", "bob.com");
    print_vault(v);

    // Create a temporary file template (must end in XXXXXX for mkstemp)
    char template[] = "/tmp/vaultjsonXXXXXX";
    int fd = mkstemp(template);
    if(fd < 0) {
        perror("mkstemp failed");
        return;
    }

    // Write the JSON data (assumed to be null-terminated) into the temporary file
    write(fd, (char*)v->data, strlen((char*)v->data));
    write(fd, "\n", 1);
    close(fd);

    // Build and execute command to open vim on the temporary file
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vim %s", template);
    system(cmd);

    // After Vim exits, re-read the file contents
    FILE *f = fopen(template, "r");
    if(!f){
        perror("fopen failed");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    char *buffer = malloc(fsize + 1);
    if(!buffer){
        perror("malloc failed");
        fclose(f);
        return;
    }
    fread(buffer, 1, fsize, f);
    buffer[fsize] = '\0';
    fclose(f);

    printf("Edited JSON:\n%s\n", buffer);
    free(buffer);
    // Clean up by removing the temporary file
    unlink(template);
}

int main(){
    
    // test_basic_vault_func();
    printf("Done basic functionality test!");

    // printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    // test_file_writing_reading();
    // printf("Done file writing test!");

    // test_basic_vault_func();
    // test_file_writing_reading();
    // create_vault();
    printf("Testing pipe!\n");
    test_pipe_json();
    
    // test_writing_json();
    // secure_print("hello", 5);
    // char* password;
    // secure_read(&password, "enter pass: ");
    // printf("pass received: %s", password);
}
