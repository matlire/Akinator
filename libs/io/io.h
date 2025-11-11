#ifndef IO_H
#define IO_H

#include <stddef.h>
#include "../logging/logging.h"

#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ctype.h>

typedef struct
{
    FILE* in_file;
    FILE* out_file;
    
    char*  buffer;
    size_t buffer_size;
} operational_data_t;

/*
    Function to parse shell arguments (files to interact with)
*/
size_t parse_arguments(const int argc, char* const argv[],          \
                       const char** in_file, const char** out_file);

/*
    Function to load file under name in mode (r, w, a, etc)
*/
FILE   *load_file (const char * const name, const char * const mode);

/*
    Function to read buffer_size bytes from file into buffer 
*/
size_t  read_file (FILE *file, operational_data_t* op_data);

/*
    Function to get file size by file's name
*/
ssize_t get_file_size_stat (const char * const filename);

size_t clean_file(const char * const filename);

#endif
