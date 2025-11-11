#ifndef AKINATOR_H
#define AKINATOR_H

#include <string.h>

#include "../libs/types.h"
#include "../libs/logging/logging.h"
#include "../tree/tree.h"
#include "../tree/dump/dump.h"
#include "../libs/io/io.h"

typedef enum
{
    DIR_IGNORE = 2,
    DIR_YES    = 1, // Left
    DIR_NO     = 0  // Right
} directions_e;

typedef struct
{
    tree_t* tree;
    node_t* curr;
    char*   path;
} akinator_t;

#define CREATE_AKINATOR(akinator_name) \
    akinator_t akinator_name = { 0 };  \
    akinator_ctor(&(akinator_name))

err_t akinator_ctor (akinator_t* akin);
err_t akinator_dtor (akinator_t* akin);
err_t akinator_reset(akinator_t* akin);

err_t guess          (akinator_t* akin, int guess);
err_t insert_object  (akinator_t* akin, char* value, node_t* after, directions_e direction, int move_to);
err_t describe_object(akinator_t* akin, char* object);

err_t write_file(akinator_t* akin, char* filename);

err_t akinator_run(akinator_t* akin);

#endif
