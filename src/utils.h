#pragma once
#include <cjson/cJSON.h>
#include <stdio.h>


void print_bytes(unsigned char* bytes, size_t len){
    for (int i = 0; i < len; i++){
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}
