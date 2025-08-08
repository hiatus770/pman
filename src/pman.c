#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string.h>

#include "vault.h"
#include "cli.h"

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

/*
 * CLI Usage
 * pman open home.vault  // This will open the vault and prompt you for the password to open it
 * Once you are inside the vault you can do a few things
 * list -- lists all entries (not password information)
 * add -- prompts you to make a new entry
 *          -- can auto generate a password for you as well when you are being prompted
 * edit -- can open a cli for the json file possibly?
 * manual -- you can edit the json file manually as well
 */
int main(int argc, char* argv[]){
    // Parsing pman input
    add_tools();
    parse_input(argc, argv);
}
