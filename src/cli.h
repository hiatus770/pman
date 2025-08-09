#pragma once

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "utils.h"
#include "vault.h"

#define n_loop(n) for (int i = 0; i < n; i++)
#define PASSWORD_BYTES 32

typedef struct {
    char* identifier;
    void (*func)(int argc, char* args[]);
    char* help_string;
} tool;


int tool_count = 0;
tool tools[30];


void add_tool(char* identifier, void (*func)(int argc, char* args[]), char* help_string){
    tools[tool_count++] = (tool){.identifier = identifier, .func = func, .help_string =  help_string};
}

void print_help(){
    printf("Usage for pman: \n");
    for (int i = 0; i < tool_count; i++){
        printf("\t%s\t%s\n", tools[i].identifier , tools[i].help_string);
    }
}

int is_keyword(char* string){
    // printf("\t\tChecking keyword!\n");
    for (int i = 0; i < tool_count; i++){
        // printf("Comparing %s and %s\n", string, tools[i].identifier);
        if (strcmp(string, tools[i].identifier) == 0){
            // printf("Found keyword %s\n", string);
            return 1;
        }
    }
    return 0;
}

int get_tool(char* identifier){
    for (int i = 0; i < tool_count; i++){
        if (strcmp(identifier, tools[i].identifier) == 0){
               return i;
        }
    }
    return -1;
}

int find_next_keyword(char* argv[], int cur_ind, int argc){
    // printf("Finding keyword!\n");
    for (int i = cur_ind+1; i < argc; i++){
        // printf("argv[%d] = %s\n", i, argv[i] ? argv[i] : "NULL");
        if (is_keyword(argv[i]) == 1){
            return i;
        }
    }
    return argc;
}

void parse_input(int argc, char* argv[]){
    if (DEBUG){
        printf("Calling parse input!\n");
    };

    if (DEBUG) {
        n_loop(argc){
            printf("\t%d:%s\t",i, argv[i]);
        }
        printf("\n");
    }
    if (argc == 1){
        print_help();
        return;
    }
    // We want to split by identifier, so we basically just pass the argc and argv split on the fact if its an actual like tool we let them use
    int index = 1;
    while (index < argc){
        if (find_next_keyword(argv, index-1, argc) < argc+1){
            index = find_next_keyword(argv, index-1, argc);
            // printf("Keyword at %d\n", index);
            // Now that we have the new keyword we need to call the correct function only after we chose the correct elems
            // printf("\tFinding next keyword!\n");
            int next_ind = find_next_keyword(argv, index, argc);
            // printf("Next ind is %d\n", next_ind);

            char* args[next_ind - index];
            n_loop(next_ind - index - 1)
            {
                args[i] = argv[index + i + 1];
            }
            tools[get_tool(argv[index])].func(next_ind - index - 1, args);

            index = next_ind;


        } else {
            printf("idk how you got here\n");
        }
    }

}

void gen_secure_password(char* buffer, size_t buf_size) {
    // buf_size should be at least (PASSWORD_BYTES * 2 + 1) for hex encoding.
    unsigned char rand_bytes[PASSWORD_BYTES];
    if (RAND_bytes(rand_bytes, PASSWORD_BYTES) != 1) {
        // RAND_bytes failed, fallback to a default (not recommended for production)
        snprintf(buffer, buf_size, "fallbackpass");
        return;
    }
    // Convert each random byte into two hex characters

    const char hex_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()[]{},./?~`";
    for (int i = 0; i < PASSWORD_BYTES; i++) {
        buffer[i] = hex_chars[rand() % (82)];
    }
    buffer[PASSWORD_BYTES] = '\0';
}

void repl(char* directory) {
    printf("Opening vault: %s\n", directory);
    vault* v = get_vault(directory);
    if (!v) {
        fprintf(stderr, "Failed to open vault.\n");
        return;
    }

    char* password = (char*)secure_malloc(100);
    secure_read(&password, "Enter vault password: ");
    if (!password) {
        fprintf(stderr, "Failed to get secure input.\n");
        return;
    }

    unsigned char* key = generate_key_256(password, strlen(password), v->salt, key);
    if (!key) {
        fprintf(stderr, "Key generation failed.\n");
        secure_free(password, 100);
        return;
    }

    decrypt_vault(v, key);
    memset(password, 0, strlen(password));
    secure_free(password, 100);

    const char *parse_end = NULL;
    cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
    if (!json_array) {
        printf("Wrong password\n");
        return;
    }
    cJSON_Delete(json_array);

    printf("Vault open. Available commands: list, add, modify, info, write, exit\n");

    char command[256];
    int running = 1;
    while (running) {
        printf("pman> ");
        if (!fgets(command, sizeof(command), stdin))
            break;
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n')
            command[len - 1] = '\0';

        enum { CMD_UNKNOWN, CMD_LIST, CMD_ADD, CMD_MODIFY, CMD_INFO, CMD_WRITE, CMD_EDIT, CMD_EXIT, CMD_COPY } cmd = CMD_UNKNOWN;
        if (strcmp(command, "list") == 0) cmd = CMD_LIST;
        else if (strcmp(command, "add") == 0) cmd = CMD_ADD;
        else if (strcmp(command, "modify") == 0) cmd = CMD_MODIFY;
        else if (strcmp(command, "info") == 0) cmd = CMD_INFO;
        else if (strcmp(command, "write") == 0) cmd = CMD_WRITE;
        else if (strcmp(command, "edit") == 0) cmd = CMD_EDIT;
        else if (strcmp(command, "exit") == 0) cmd = CMD_EXIT;
        else if (strcmp(command, "copy") == 0) cmd = CMD_COPY;


        switch (cmd) {
            case CMD_LIST: {
                const char *parse_end = NULL;
                cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
                if (!json_array) {
                    printf("Error parsing vault entries.\n");
                } else {
                    int count = cJSON_GetArraySize(json_array);
                    printf("Vault entries (%d):\n", count);
                    for (int i = 0; i < count; i++) {
                        cJSON *entry = cJSON_GetArrayItem(json_array, i);
                        cJSON *url = cJSON_GetObjectItem(entry, entry_field_string[URL]);
                        printf("[%d] %s\n", i, cJSON_PrintUnformatted(url));
                    }
                    cJSON_Delete(json_array);
                }
                break;
            }
            case CMD_ADD: {
                char email[256], password[256], notes[256], url[256];
                printf("Enter email: ");
                if (!fgets(email, sizeof(email), stdin))
                    break;
                email[strcspn(email, "\n")] = '\0';


                printf("Enter password (leave blank to autogenerate): ");
                int generated = 0;
                char auto_pass[(PASSWORD_BYTES * 2) + 1];
                if (!fgets(password, sizeof(password), stdin))
                    break;
                if (strcmp("\n", password) == 0){
                    generated = 1;
                    gen_secure_password(auto_pass, sizeof(auto_pass));
                    printf("Using auto-generated secure password: %s\n", auto_pass);
                } else {
                    password[strcspn(password, "\n")] = '\0';
                }


                printf("Enter notes: ");
                if (!fgets(notes, sizeof(notes), stdin))
                    break;
                notes[strcspn(notes, "\n")] = '\0';

                printf("Enter URL: ");
                if (!fgets(url, sizeof(url), stdin))
                    break;
                url[strcspn(url, "\n")] = '\0';


                add_entry(v, email, (generated == 1) ? auto_pass : password, notes, url);
                printf("Entry added.\n");
                break;
            }
            case CMD_MODIFY: {
                char index_str[16];
                printf("Enter index to modify: ");
                if (!fgets(index_str, sizeof(index_str), stdin))
                    break;
                int index = atoi(index_str);

                printf("Enter new notes: ");
                char new_notes[256];
                if (!fgets(new_notes, sizeof(new_notes), stdin))
                    break;
                new_notes[strcspn(new_notes, "\n")] = '\0';

                const char *parse_end = NULL;
                cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
                if (!json_array) {
                    printf("Error parsing vault for modification.\n");
                } else {
                    cJSON *entry = cJSON_GetArrayItem(json_array, index);
                    if (entry) {
                        cJSON *notes_obj = cJSON_GetObjectItem(entry, "notes");
                        if (notes_obj) {
                            cJSON_SetValuestring(notes_obj, new_notes);
                        } else {
                            cJSON_AddStringToObject(entry, "notes", new_notes);
                        }
                        char* updated_data = cJSON_PrintUnformatted(json_array);
                        if (updated_data) {
                            secure_free(v->data, v->data_length);
                            int new_length = strlen(updated_data);
                            v->data = (unsigned char*)secure_malloc(new_length + 1);
                            memcpy(v->data, updated_data, new_length + 1);
                            v->data_length = new_length;
                            free(updated_data);
                            printf("Entry modified.\n");
                        }
                    } else {
                        printf("No entry at index %d.\n", index);
                    }
                    cJSON_Delete(json_array);
                }
                break;
            }
            case CMD_INFO: {
                char index_str[16];
                printf("Enter index for info: ");
                if (!fgets(index_str, sizeof(index_str), stdin))
                    break;
                int index = atoi(index_str);

                const char *parse_end = NULL;
                cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
                if (!json_array) {
                    printf("Error parsing vault.\n");
                } else {
                    cJSON *entry = cJSON_GetArrayItem(json_array, index);
                    if (entry) {
                        cJSON *email_obj = cJSON_GetObjectItem(entry, "email");
                        cJSON *pass_obj  = cJSON_GetObjectItem(entry, "password");
                        printf("Username/Email: %s\n", email_obj ? email_obj->valuestring : "(none)");
                        printf("Password: %s\n", pass_obj ? pass_obj->valuestring : "(none)");
                    } else {
                        printf("No entry at index %d.\n", index);
                    }
                    cJSON_Delete(json_array);
                }
                break;
            }
            case CMD_WRITE: {
                encrypt_vault(v, key);
                write_vault(v, directory);
                decrypt_vault(v, key);
                break;
            }
            case CMD_EDIT: {
                /* Create a temporary file template (must end in XXXXXX for mkstemp) */
                char template[] = "/tmp/vaultjsonXXXXXX";
                int fd = mkstemp(template);
                if(fd < 0) {
                    perror("mkstemp failed");
                    break;
                }

                /* Write the current decrypted JSON data into the temporary file. */
                write(fd, (char*)v->data, v->data_length);
                close(fd);

                /* Build and execute the command to open Vim on the temporary file */
                char vimCmd[256];
                snprintf(vimCmd, sizeof(vimCmd), "vim %s", template);
                system(vimCmd);

                /* After Vim exits, re-read the file contents */
                FILE *f = fopen(template, "r");
                if(!f){
                    perror("fopen failed");
                    break;
                }
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                rewind(f);
                /* Allocate temporary buffer with malloc because we will later copy into secure memory */
                char *temp_buffer = malloc(fsize + 1);
                if(!temp_buffer){
                    perror("malloc failed");
                    fclose(f);
                    break;
                }
                fread(temp_buffer, 1, fsize, f);
                temp_buffer[fsize] = '\\0';
                fclose(f);
                unlink(template);

                /* Allocate new secure memory for the edited JSON */
                unsigned char *new_data = secure_malloc(fsize + 1);
                if(!new_data) {
                    perror("secure_malloc failed");
                    free(temp_buffer);
                    break;
                }
                memcpy(new_data, temp_buffer, fsize + 1);
                free(temp_buffer);

                /* Free the old vault data using secure_free */
                secure_free(v->data, v->data_length);
                v->data = new_data;
                v->data_length = fsize;
                printf("Vault updated with edited JSON.\\n");
                break;
            }
            case CMD_COPY:
            {

                char index_str[16];
                printf("Enter index for copy: ");
                if (!fgets(index_str, sizeof(index_str), stdin))
                    break;
                int index = atoi(index_str);

                const char *parse_end = NULL;
                cJSON *json_array = cJSON_ParseWithLengthOpts((char*)v->data, v->data_length, &parse_end, 0);
                if (!json_array) {
                    printf("Error parsing vault.\n");
                } else {
                    cJSON *entry = cJSON_GetArrayItem(json_array, index);
                    if (entry) {
                        cJSON *email_obj = cJSON_GetObjectItem(entry, "email");
                        cJSON *pass_obj  = cJSON_GetObjectItem(entry, "password");
                        char copy_cmd[256];
                        snprintf(copy_cmd, sizeof(copy_cmd), "wl-copy %s", cJSON_PrintUnformatted(pass_obj));
                        system(copy_cmd);
                    } else {
                        printf("No entry at index %d.\n", index);
                    }
                    cJSON_Delete(json_array);
                }
                printf("Copied to clipboard");
                break;

            }
            case CMD_EXIT:
                running = 0;
                break;
            default:
                printf("Unknown command. Available commands: list, add, modify, info, write, exit.\n");
        }
    }

    printf("Exiting pman\n");
    encrypt_vault(v, key);
    write_vault(v, directory);
    secure_free(v->data, v->data_length);
    secure_free(v, sizeof(vault));
    secure_free(key, 32);
}


void init(int argc, char* argv[]){
    if (argc != 1){
        printf("Expected 1 argument for init, got %d", argc);
        return;
    }

    // Initializing vault
    vault* v = init_vault();
    print_vault(v);
    char* password = (char*)secure_malloc(100);
    secure_read(&password, "Enter new vault password: ");
    unsigned char* key;
    key = generate_key_256(password, strlen(password), v->salt, key);
    encrypt_vault(v, key);
    print_vault(v);

    printf("Wrote vault file\n");
    write_vault(v, argv[0]);
}

void help(int argc, char* argv[]){
    print_help();
}

void open(int argc, char* argv[]){
    if (argc == 0){
        printf("No arguments passed into open, exiting\n");
        return;
    }
    if (DEBUG) printf("argc %d for function call open\n", argc);
    if (argc == 1){
        repl(argv[0]); return;
    }

    printf("Too many arguments for open");
}

void add_tools(){
    add_tool("help", &help, "prints this message and then exits");
    add_tool("open", &open, "opens a vault, must pass a directory or it will error. Usage is `pman open file.vault`");
    add_tool("init", &init, "initializes a vault, usage   `pman init file.vault`");
}
