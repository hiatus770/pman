CC=gcc
CFLAGS= -lcrypto -lssl -lcjson

# Find all include files
include_files=$(wildcard ./src/*)

# Find all files that the project is dependent on
dep_files=$(wildcard makefile ./test/* ./src/* ./src/*/*)

# Find all the source files
src_files=$(wildcard ./src/*.c)

# Find all the test files in the test directory
src_files_test=$(wildcard ./test/*.c)


build/main: $(dep_files)
	@echo "Making main c file"
	gcc -I/usr/bin/include -o build/main -g $(src_files) $(CFLAGS)

build/test: $(dep_files)
	@echo "Making test file"
	gcc -I/usr/bin/include -o build/test -g $(src_files_test) $(CFLAGS)
