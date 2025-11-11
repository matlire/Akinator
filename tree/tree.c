#include "tree.h"

err_t node_ctor(node_t * const node)
{
    if (!CHECK(ERROR, node != NULL, "node_ctor: node is NULL"))
        return ERR_BAD_ARG;

    node->data  = 0;
    node->left  = NULL;
    node->right = NULL;
    return OK;
}

err_t node_dtor(node_t * node)
{
    if (node == NULL) return ERR_BAD_ARG;
    if (node->data) free(node->data);
    free(node);
    return OK;
}

err_t tree_ctor(tree_t * const tree)
{
    if (!CHECK(ERROR, tree != NULL, "tree_ctor: tree is NULL"))
        return ERR_BAD_ARG;

    tree->nodes_amount = 0;
    tree->root = NULL;
    return OK;
}

err_t tree_dtor(tree_t * const tree)
{
    if (!CHECK(ERROR, tree != NULL, "tree_dtor: tree is NULL"))
        return ERR_BAD_ARG;

    (void)tree_clear(tree);
    tree->root = NULL;
    tree->nodes_amount = 0;
    return OK;
}

err_t tree_verify(const tree_t * const tree)
{
    if (!CHECK(ERROR, tree != NULL, "tree_verify: tree is NULL"))
        return ERR_BAD_ARG;

    if (!CHECK(ERROR,
               !(tree->nodes_amount > 0 && tree->root == NULL),
               "tree_verify: nodes_amount=%zu but root is NULL",
               (size_t)tree->nodes_amount))
        return ERR_CORRUPT;

    return OK;
}


err_t tree_fprint_node(FILE *out, const node_t *const node, size_t iter)
{
    if (!CHECK(ERROR, out != NULL, "tree_fprintf_node: out is NULL"))
        return ERR_BAD_ARG;
    if (!CHECK(ERROR, node != NULL, "tree_fprintf_node: node is NULL"))
        return ERR_BAD_ARG;
    if (!CHECK(ERROR, iter <= MAX_RECURSION_LIMIT,
               "tree_fprintf_node: recursion limit exceeded (%zu > %zu)",
               iter, (size_t)MAX_RECURSION_LIMIT))
        return ERR_CORRUPT;

    iter += 1;

    if (node->data) 
    {
        fprintf(out, "(");
        fprintf(out, "%s", node->data);
        fprintf(out, "\"");
    }

    if (node->left)
        (void)tree_fprint_node(out, node->left, iter);
    else
        fprintf(out, " nil");

    if (node->right)
        (void)tree_fprint_node(out, node->right, iter);
    else
        fprintf(out, " nil");

    fprintf(out, ")");
    return OK;
}

err_t tree_fprint(FILE *out, const tree_t *const tree)
{
    if (!CHECK(ERROR, out != NULL, "tree_fprintf: out is NULL"))
        return ERR_BAD_ARG;
    if (!CHECK(ERROR, tree != NULL, "tree_fprintf: tree is NULL"))
        return ERR_BAD_ARG;

    fwrite("\xEF\xBB\xBF", 1, 3, out);

    if (tree->root)
        return tree_fprint_node(out, tree->root, 0);

    fputs("nil", out);
    return OK;
}

err_t tree_delete_node(node_t * node, size_t iter)
{
    if (!CHECK(ERROR, node != NULL, "tree_delete_node: node is NULL"))
        return ERR_BAD_ARG;

    if (!CHECK(ERROR, iter <= MAX_RECURSION_LIMIT,
               "tree_delete_node: recursion limit exceeded (%zu > %zu)",
               iter, (size_t)MAX_RECURSION_LIMIT))
        return ERR_CORRUPT;

    iter += 1;

    if (node->left  != NULL)
        if (!CHECK(ERROR, tree_delete_node(node->left,  iter) == OK,
                   "tree_delete_node: failed to delete left subtree"))
            return ERR_CORRUPT;

    if (node->right != NULL)
        if (!CHECK(ERROR, tree_delete_node(node->right, iter) == OK,
                   "tree_delete_node: failed to delete right subtree"))
            return ERR_CORRUPT;

    (void)node_dtor(node);
    return OK;
}

err_t tree_clear(const tree_t * const tree)
{
    if (!CHECK(ERROR, tree != NULL, "tree_clear: tree is NULL"))
        return ERR_BAD_ARG;

    if (tree->root == NULL)
        return OK;

    if (!CHECK(ERROR, tree_delete_node(tree->root, 0) == OK,
               "tree_clear: failed to delete nodes"))
        return ERR_CORRUPT;

    return OK;
}

err_t tree_insert(tree_t * const tree, const tree_elem_t data)
{
    if (!CHECK(ERROR, tree != NULL, "tree_insert: tree is NULL"))
        return ERR_BAD_ARG;

    node_t *node = (node_t*)calloc(1, sizeof(*node));
    if (!CHECK(ERROR, node != NULL, "tree_insert: node alloc failed"))
        return ERR_ALLOC;

    if (data != NULL) {
        size_t len = strlen(data);
        char *copy = (char*)calloc(len + 1, 1);
        if (!CHECK(ERROR, copy != NULL, "tree_insert: data alloc failed")) {
            free(node);
            return ERR_ALLOC;
        }
        memcpy(copy, data, len);
        node->data = copy;
    }

    tree->nodes_amount += 1;

    if (tree->root == NULL) {
        tree->root = node;
        return OK;
    }

    node_t *cur = tree->root;
    size_t  i   = 0;

    for (; i < MAX_RECURSION_LIMIT; ++i) {
        if (cur->left == NULL)  { cur->left  = node; break; }
        if (cur->right == NULL) { cur->right = node; break; }

        int c = atoi(cur->data ? cur->data : "0");
        int d = atoi(node->data ? node->data : "0");
        cur = (c >= d) ? cur->left : cur->right;
    }

    if (!CHECK(ERROR, i < MAX_RECURSION_LIMIT,
               "tree_insert: descent exceeded limit")) {
        free(node->data);
        free(node);
        tree->nodes_amount -= 1;
        return ERR_CORRUPT;
    }

    return OK;
}

