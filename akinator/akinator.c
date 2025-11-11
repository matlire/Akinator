#include "akinator.h"

#define TDUMP(tree_ptr, title_str) \
    tree_dump((tree_ptr), (title_str), "tgdump.html")

err_t akinator_ctor (akinator_t* akin)
{
    tree_dump_reset("tgdump.html");
    tree_t *t = calloc(1, sizeof *t);
    if (!t) return ERR_ALLOC;
    if (tree_ctor(t) != OK) { free(t); return ERR_BAD_ARG; }
    akin->tree = t;
    akin->curr = NULL;
    return OK;
}

err_t akinator_dtor (akinator_t* akin)
{
    akin->curr = NULL;
    err_t ret = tree_dtor(akin->tree);
    free(akin->tree);
    akin->tree = NULL;
    return ret;
}

err_t akinator_reset(akinator_t* akin)
{
    akin->curr = akin->tree->root;
    return OK;
}

err_t guess(akinator_t* akin, int guess)
{
    switch (guess)
    {
        case 0:
            akin->curr = akin->curr->right;
            break;
        case 1:
            akin->curr = akin->curr->left;
            break;
        default:
            return ERR_BAD_ARG;
    }
    return OK;
}

err_t insert_object(akinator_t* akin, char* value, node_t* after, directions_e direction, int move_to)
{
    if (!akin || !akin->tree || !value) return ERR_BAD_ARG;
    if ((direction != DIR_IGNORE && direction != DIR_NO && direction != DIR_YES) ||
        (move_to != DIR_IGNORE && move_to != DIR_NO && move_to != DIR_YES)) return ERR_BAD_ARG;

    node_t *node = (node_t*)calloc(1, sizeof(*node));
    if (!node) return ERR_ALLOC;

    size_t len = strlen(value);
    node->data = (char*)calloc(len + 1, 1);
    if (!node->data) { free(node); return ERR_ALLOC; }
    memcpy(node->data, value, len);

    if (direction == DIR_IGNORE) {
        if (akin->tree->root == NULL) 
        {
            akin->tree->root = node;
            akin->tree->nodes_amount += 1;
            return OK;
        }
        free(node->data);
        free(node);
        return ERR_BAD_ARG;
    }

    if (!after) 
    {
        free(node->data);
        free(node);
        return ERR_BAD_ARG;
    }

    if (move_to == DIR_IGNORE) 
    {
        node_t *cur = after;
        if (direction == DIR_YES) {
            while (cur->left) cur = cur->left;
            cur->left = node;
        } else {
            while (cur->right) cur = cur->right;
            cur->right = node;
        }
        akin->tree->nodes_amount += 1;
        return OK;
    }

    node_t **slot = (direction == DIR_YES) ? &after->left : &after->right;
    node_t *old = *slot;
    *slot = node;
    if (move_to == DIR_YES) node->left = old; else node->right = old;

    akin->tree->nodes_amount += 1;
    return OK;
}


#define IS_LEAF(nd) (!(nd)->left && !(nd)->right)

static inline int push_child(node_t        **stack_nodes,
                             unsigned char  *state,
                             int            *edge_dir,
                             int            *top,
                             const node_t   *child,
                             int             dir)
{
    if (!child) return 0;
    ++(*top);
    if (*top > MAX_RECURSION_LIMIT) return -1;
    stack_nodes[*top] = (node_t*)child;
    state[*top] = 0;
    edge_dir[*top] = dir;
    return 1;
}

static void print_path_desc(node_t **stack_nodes, int *edge_dir, int top, const char *object)
{
    printf("%s", object);
    if (top > 0) printf(" ");
    for (int i = 0; i < top; ++i) 
    {
        if (i > 0) printf(" и ");
        if (edge_dir[i + 1] == DIR_YES)
            printf("\"%s\"", stack_nodes[i]->data ? stack_nodes[i]->data : "");
        else
            printf("не \"%s\"", stack_nodes[i]->data ? stack_nodes[i]->data : "");
    }
    printf("\n");
}

err_t describe_object(akinator_t* akin, char* object)
{
    if (!akin || !object || !akin->tree || !akin->tree->root) return ERR_BAD_ARG;

    node_t*       stack_nodes[MAX_RECURSION_LIMIT + 1] = { 0 };
    unsigned char state[MAX_RECURSION_LIMIT + 1]       = { 0 };
    int           edge_dir[MAX_RECURSION_LIMIT + 1]    = { 0 };

    int top        = 0;
    stack_nodes[0] = akin->tree->root;
    state[0]       = 0;
    edge_dir[0]    = -1;

    while (top >= 0) {
        node_t* n = stack_nodes[top];

        if (IS_LEAF(n) && state[top] == 0) 
        {
            if (n->data && strcmp(n->data, object) == 0) {
                print_path_desc(stack_nodes, edge_dir, top, object);
                return OK;
            }
            state[top] = 2;
        }

        if (state[top] == 0) 
        {
            state[top] = 1;
            int r = push_child(stack_nodes, state, edge_dir, &top, n->left, DIR_YES);
            if (r < 0) return ERR_CORRUPT;
            if (r > 0) continue;
        }

        if (state[top] == 1) 
        {
            state[top] = 2;
            int r = push_child(stack_nodes, state, edge_dir, &top, n->right, DIR_NO);
            if (r < 0) return ERR_CORRUPT;
            if (r > 0) continue;
        }

        if (state[top] == 2) --top;
    }

    return ERR_BAD_ARG;
}

err_t write_file(akinator_t* akin, char* filename)
{
    err_t ret = clean_file(filename);
    if (ret != 1) return ERR_CORRUPT;
    FILE* file = load_file(filename, "wb");
    ret = tree_fprint(file, akin->tree);
    fclose(file);
    return ret;
}

static int ru_is_yes(const char *s) 
{
    return strcmp(s,"д")==0  || strcmp(s,"Д")==0  ||
           strcmp(s,"да")==0 || strcmp(s,"Да")==0 || strcmp(s,"ДА")==0;
}

static int ru_is_no(const char *s) 
{
    return strcmp(s,"н")==0   || strcmp(s,"Н")==0   ||
           strcmp(s,"нет")==0 || strcmp(s,"Нет")==0 || strcmp(s,"НЕТ")==0;
}

static const char* ltrim_spaces(const char *s) 
{
    while (*s==' ') s++;
    return s;
}

static void rtrim_spaces(char *s) 
{
    size_t l = strlen(s);
    while (l && s[l-1]==' ') s[--l]='\0';
}

static void ensure_qmark(char *s, size_t cap) 
{
    size_t l = strlen(s);
    if (l==0 || s[l-1] != '?') 
    {
        if (l < cap-1) { s[l++]='?'; s[l]='\0'; }
        else { s[cap-2]='?'; s[cap-1]='\0'; }
    }
}

static int detect_negation(const char *s) 
{
    return strncmp(s,"не ", strlen("не "))==0   ||
           strncmp(s,"Не ", strlen("Не "))==0   ||
           strncmp(s,"НЕ ", strlen("НЕ "))==0   ||
           strstr(s," не ") || strstr(s," Не ") || strstr(s," НЕ ");
}

static void normalize_predicate(const char *in, char *out, size_t cap, int *is_neg) 
{
    const char *p = ltrim_spaces(in);
    *is_neg       = detect_negation(p);

    if      (strncmp(p, "не ", strlen("не ")) == 0) p += strlen("не ");
    else if (strncmp(p, "Не ", strlen("Не ")) == 0) p += strlen("Не ");
    else if (strncmp(p, "НЕ ", strlen("НЕ ")) == 0) p += strlen("НЕ ");

    size_t l = strlen(p);
    if (l >= cap) l = cap-1;
    memcpy(out, p, l); out[l] = '\0';
    rtrim_spaces(out);
    ensure_qmark(out, cap);
}

static void flush_line(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

static int read_line(char *buf, size_t cap) {
    size_t i = 0;
    int c = getchar();
    if (c == EOF) return -1;
    while (c != '\n' && c != EOF) {
        if (i + 1 < cap) buf[i++] = (char)c;
        c = getchar();
    }
    if (i && buf[i-1] == '\r') i--;
    buf[i] = '\0';
    return (int)i;
}

err_t akinator_run(akinator_t* akin)
{
    if (!akin || !akin->tree || !akin->tree->root) return ERR_BAD_ARG;
    node_t* parent = NULL;
    akin->curr = akin->tree->root;

    for (;;) {
        node_t* n = akin->curr;

        if (!n->left && !n->right) {
            char ans[8];
            printf("Это %s? (да/нет): ", n->data ? n->data : "");
            fflush(stdout);
            if (scanf("%7s", ans) != 1) return ERR_BAD_ARG;
            scanf("%*[^\n]"); scanf("%*c");
            if (ru_is_yes(ans)) { printf("Прочитан!\n"); return OK; }

            char obj[512];
            printf("Что ты хотел чтобы я угадал: ");
            fflush(stdout);
            int r1 = scanf("%511[^\n]", obj);
            if (r1 == EOF) return ERR_BAD_ARG;
            scanf("%*[^\n]"); scanf("%*c");
            if (r1 == 0) obj[0] = '\0';

            char pred[512]={0}, crit[512]={0};
            printf("Чем \"%s\" отличается \"%s\"? \"%s\" ...", obj, n->data ? n->data : "", obj);
            fflush(stdout);
            int r2 = scanf("%511[^\n]", pred);
            if (r2 == EOF) return ERR_BAD_ARG;
            scanf("%*[^\n]"); scanf("%*c");
            if (r2 == 0) pred[0]='\0';

            int neg = 0;
            normalize_predicate(pred, crit, sizeof(crit), &neg);

            if (parent == NULL) 
            {
                node_t* old_root = akin->tree->root;
                node_t* q = (node_t*)calloc(1, sizeof(*q));
                if (!q) return ERR_ALLOC;

                size_t lp = strlen(crit);
                q->data = (char*)calloc(lp + 1, 1);
                if (!q->data) { free(q); return ERR_ALLOC; }

                memcpy(q->data, crit, lp);
                if (!neg) q->right = old_root; else q->left = old_root;

                akin->tree->root = q;
                akin->tree->nodes_amount += 1;
                if (!neg) 
                    { if (insert_object(akin, obj, q, DIR_YES, DIR_IGNORE) != OK) return ERR_CORRUPT; }
                else 
                    { if (insert_object(akin, obj, q, DIR_NO, DIR_IGNORE) != OK) return ERR_CORRUPT; }
                printf("Спасибо, я когда-нибудь все запомню...\n");
                return OK;
            } else 
            {
                int dir = (parent->left == n) ? 1 : 0;
                if (!neg) 
                {
                    if (insert_object(akin, crit, parent, dir, DIR_NO) != OK) return ERR_CORRUPT;
                    node_t* q = dir ? parent->left : parent->right;
                    if (insert_object(akin, obj, q, 1, -1) != OK) return ERR_CORRUPT;
                } else 
                {
                    if (insert_object(akin, crit, parent, dir, DIR_YES) != OK) return ERR_CORRUPT;
                    node_t* q = dir ? parent->left : parent->right;
                    if (insert_object(akin, obj, q, DIR_NO, DIR_IGNORE) != OK) return ERR_CORRUPT;
                }
                printf("Спасибо, я когда-нибудь все запомню.\n");
                return OK;
            }
        }

        char ans[8];
        printf("%s (да/нет): ", n->data ? n->data : "");
        fflush(stdout);
        if (scanf("%7s", ans) != 1) return ERR_BAD_ARG;
        scanf("%*[^\n]"); scanf("%*c");
        parent = n;
        if      (ru_is_yes(ans)) akin->curr = n->left  ? n->left  : n->right;
        else if (ru_is_no(ans))  akin->curr = n->right ? n->right : n->left;
    }
}

