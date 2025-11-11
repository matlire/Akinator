#ifndef TREE_H
#define TREE_H

#include "../libs/logging/logging.h"
#include "../libs/types.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define MAX_RECURSION_LIMIT 4096

typedef char* tree_elem_t;

typedef struct node_t
{
    tree_elem_t    data;
    struct node_t* left;
    struct node_t* right;
} node_t;

typedef struct
{
    size_t  nodes_amount;
    node_t* root;
} tree_t;

#define CREATE_TREE(tree_name) \
    tree_t tree_name = { 0 };  \
    tree_ctor(&(tree_name))

#define CREATE_NODE(node_name)                      \
    node_t* node_name = calloc(1, sizeof(node_t));  \
    node_ctor((node_name))

err_t node_ctor(node_t * const node);
err_t node_dtor(node_t * node);

err_t tree_ctor(tree_t * const tree);
err_t tree_dtor(tree_t * const tree);

err_t tree_verify(const tree_t * const tree);

err_t tree_fprint_node(FILE *out, const node_t * const node, size_t iter);
err_t tree_fprint     (FILE *out, const tree_t * const tree);

err_t tree_delete_node(node_t * node, size_t iter);
err_t tree_clear      (const tree_t * const tree);

err_t tree_insert     (tree_t * const tree, const tree_elem_t data);

#endif
