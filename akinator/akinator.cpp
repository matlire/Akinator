#include "akinator.h"
#include <festival/festival.h>
#include <stdarg.h>
#include <sanitizer/lsan_interface.h>

#define TDUMP(tree_ptr, title_str) \
    tree_dump((tree_ptr), (title_str), "tgdump.html")

#define SAY_AND_PRINT_BUFF 512

static void say_and_print(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char buffer[SAY_AND_PRINT_BUFF] = { 0 };
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    printf("%s", buffer);
    fflush(stdout);
    festival_say_text(buffer);
}


err_t akinator_ctor (akinator_t* akin)
{ 
    __lsan_disable();
    festival_initialize(1, 10000000);
    festival_eval_command("(Parameter.set 'Input_Text_Format 'utf8)");
    festival_eval_command("(Parameter.set 'Language 'russian)");
    festival_eval_command("(voice_msu_ru_nsh_clunits)");
    __lsan_enable();

    tree_dump_reset("tgdump.html");
    tree_t t = {  };
    if (tree_ctor(&t) != OK) return ERR_BAD_ARG;
    akin->tree = t;
    akin->curr = NULL;
    return OK;
}

err_t akinator_dtor (akinator_t* akin)
{
    akin->curr = NULL;
    err_t ret = tree_dtor(&(akin->tree));

    festival_tidy_up();
    return ret;
}

err_t akinator_reset(akinator_t* akin)
{
    akin->curr = akin->tree.root;
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
    if (!CHECK(ERROR, akin != NULL && value != NULL,
                 "insert_object: akin or value is NULL")) return ERR_BAD_ARG;
    if (!CHECK(ERROR,
                 (direction == DIR_IGNORE || direction == DIR_NO || direction == DIR_YES) &&
                 (move_to   == DIR_IGNORE || move_to   == DIR_NO || move_to   == DIR_YES),
                 "insert_object: direction or move_to incorrect")) return ERR_BAD_ARG;

    node_t *node = NULL;
    err_t ret = node_ctor(&node);
    if (ret != OK) return ret;

    node->data = strdup(value);
    if (node->data == NULL) 
    { 
        node_dtor(node); 
        return ERR_ALLOC; 
    }

    if (direction == DIR_IGNORE) 
    {
        if (akin->tree.root == NULL) 
        {
            akin->tree.root = node;
            akin->tree.nodes_amount += 1;
            return OK;
        }
        node_dtor(node); 
        return ERR_BAD_ARG;
    }

    if (!after) 
    {
        node_dtor(node); 
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
        akin->tree.nodes_amount += 1;
        return OK;
    }

    node_t **slot = (direction == DIR_YES) ? &after->left : &after->right;
    node_t  *old  = *slot;
    *slot = node;
    if (move_to == DIR_YES) node->left = old; 
    else node->right = old;

    akin->tree.nodes_amount += 1;
    return OK;
}

typedef enum
{
    STATE_NOT_VISITED = 0,
    STATE_LEFT_DONE   = 1,
    STATE_BOTH_DONE   = 2
} dfs_state_e;

#define IS_LEAF(nd) (!(nd)->left && !(nd)->right)

static inline int push_child(node_t        **stack_nodes,
                             dfs_state_e    *state,
                             int            *edge_dir,
                             int            *top,
                             const node_t   *child,
                             int             dir)
{
    if (!child) return 0;
    ++(*top);
    if (*top > MAX_RECURSION_LIMIT) return -1;
    stack_nodes[*top] = (node_t*)child;
    state[*top] = STATE_NOT_VISITED;
    edge_dir[*top] = dir;
    return 1;
}

static int find_object_path(akinator_t* akin, const char* object,
                            node_t** stack_nodes, dfs_state_e* state, int* edge_dir, int* out_top)
{
    int top        = 0;
    stack_nodes[0] = akin->tree.root; 
    state[0]       = STATE_NOT_VISITED;
    edge_dir[0]    = -1;

    while (top >= 0) 
    {
        node_t* n = stack_nodes[top];

        if (IS_LEAF(n) && state[top] == STATE_NOT_VISITED) 
        {
            if (n->data && strcmp(n->data, object) == 0) 
            {
                *out_top = top;
                return 1;
            }
            state[top] = STATE_BOTH_DONE;
        }

        if (state[top] == STATE_NOT_VISITED) 
        {
            state[top] = STATE_LEFT_DONE;
            int r = push_child(stack_nodes, state, edge_dir, &top, n->left, DIR_YES);
            if (r < 0) return -1;
            if (r > 0) continue;
        }

        if (state[top] == STATE_LEFT_DONE) 
        {
            state[top] = STATE_BOTH_DONE;
            int r = push_child(stack_nodes, state, edge_dir, &top, n->right, DIR_NO);
            if (r < 0) return -1;
            if (r > 0) continue;
        }

        if (state[top] == STATE_BOTH_DONE) --top;
    }

    return 0;
}

typedef struct
{
    const char *q;
    int         d;
} qdir_t;

static void print_qdir_items(const qdir_t* items, int cnt)
{
    for (int i = 0; i < cnt; ++i) {
        if (i > 0) say_and_print(" и ");
        if (items[i].d == DIR_YES)
            say_and_print("\"%s\"", items[i].q ? items[i].q : "");
        else
            say_and_print("не \"%s\"", items[i].q ? items[i].q : "");
    }
}

static int collect_path(node_t** path_nodes, int* edge_dir, int depth,
                        qdir_t* out_items, int max_items)
{
    if (depth > max_items) return -1;
    for (int i = 0; i < depth; ++i) 
    {
        out_items[i].q = path_nodes[i]->data;
        out_items[i].d = edge_dir[i + 1];
    }
    return depth;
}

static void print_path_desc(node_t **stack_nodes, int *edge_dir, int top, const char *object)
{
    say_and_print("%s", object);
    if (top > 0) say_and_print(" ");

    qdir_t items[MAX_RECURSION_LIMIT + 1];

    int cnt = collect_path(stack_nodes, edge_dir, top, items, MAX_RECURSION_LIMIT + 1);
    if (cnt < 0) { say_and_print("<слишком длинный путь>\n"); return; }

    print_qdir_items(items, cnt);
    say_and_print("\n");
}

err_t describe_object(akinator_t* akin, const char* object)
{
    if (!CHECK(ERROR, akin != NULL && object != NULL && akin->tree.root != NULL,
                 "describe_object: bad arguments")) return ERR_BAD_ARG;

    node_t*       stack_nodes[MAX_RECURSION_LIMIT + 1] = {  };
    dfs_state_e   state[MAX_RECURSION_LIMIT + 1]       = {  };
    int           edge_dir[MAX_RECURSION_LIMIT + 1]    = {  };
    int           top = -1;

    int r = find_object_path(akin, object, stack_nodes, state, edge_dir, &top);
    if (r < 0) return ERR_CORRUPT;
    if (r == 0) return ERR_BAD_ARG;

    print_path_desc(stack_nodes, edge_dir, top, object);
    return OK;
}

err_t difference_in_objects(akinator_t* akin, const char* obj1, const char* obj2)
{
    if (!CHECK(ERROR, akin != NULL && obj1 != NULL && obj2 != NULL && akin->tree.root != NULL,
                 "difference_in_objects: bad arguments")) return ERR_BAD_ARG;

    node_t*       path1_nodes[MAX_RECURSION_LIMIT + 1] = { };
    dfs_state_e   path1_state[MAX_RECURSION_LIMIT + 1] = { };
    int           path1_dir  [MAX_RECURSION_LIMIT + 1] = { };
    int           depth1 = -1;

    node_t*       path2_nodes[MAX_RECURSION_LIMIT + 1] = { };
    dfs_state_e   path2_state[MAX_RECURSION_LIMIT + 1] = { };
    int           path2_dir  [MAX_RECURSION_LIMIT + 1] = { };
    int           depth2 = -1;

    int rc = find_object_path(akin, obj1, path1_nodes, path1_state, path1_dir, &depth1);
    if (rc <= 0) return ERR_BAD_ARG;

    rc = find_object_path(akin, obj2, path2_nodes, path2_state, path2_dir, &depth2);
    if (rc <= 0) return ERR_BAD_ARG;

    qdir_t path1[MAX_RECURSION_LIMIT + 1] = { };
    qdir_t path2[MAX_RECURSION_LIMIT + 1] = { };

    int count1 = collect_path(path1_nodes, path1_dir, depth1, path1, MAX_RECURSION_LIMIT + 1);
    int count2 = collect_path(path2_nodes, path2_dir, depth2, path2, MAX_RECURSION_LIMIT + 1);
    if (count1 < 0 || count2 < 0) return ERR_CORRUPT;

    qdir_t shared[MAX_RECURSION_LIMIT + 1] = { };
    qdir_t only1 [MAX_RECURSION_LIMIT + 1] = { };
    qdir_t only2 [MAX_RECURSION_LIMIT + 1] = { };
    int shared_count = 0;
    int only1_count  = 0;
    int only2_count  = 0;

    int used2[MAX_RECURSION_LIMIT + 1] = { };

    for (int i = 0; i < count1; ++i) 
    {
        const char *q1 = path1[i].q;
        int         d1 = path1[i].d;

        int match_j = -1;
        for (int j = 0; j < count2; ++j) 
        {
            if (!used2[j]) 
            {
                const char *q2 = path2[j].q;
                if (q1 && q2 && strcmp(q1, q2) == 0) 
                {
                    match_j = j;
                    break;
                }
            }
        }

        if (match_j >= 0) 
        {
            used2[match_j] = 1;
            int d2 = path2[match_j].d;

            if (d1 == d2) 
            {
                shared[shared_count].q = q1;
                shared[shared_count].d = d1;
                ++shared_count;
            } else 
            {
                only1[only1_count].q = q1;
                only1[only1_count].d = d1;
                ++only1_count;

                only2[only2_count].q = path2[match_j].q;
                only2[only2_count].d = d2;
                ++only2_count;
            }
        } else 
        {
            only1[only1_count].q = q1;
            only1[only1_count].d = d1;
            ++only1_count;
        }
    }

    for (int j = 0; j < count2; ++j) 
    {
        if (!used2[j]) 
        {
            only2[only2_count].q = path2[j].q;
            only2[only2_count].d = path2[j].d;
            ++only2_count;
        }
    }

    int printed = 0;

    if (shared_count > 0) 
    {
        say_and_print("%s и %s ", obj1, obj2);
        print_qdir_items(shared, shared_count);
        printed = 1;
    }

    if (only1_count > 0 || only2_count > 0) 
    {
        if (printed) say_and_print(" но ");
        say_and_print("%s ", obj1);

        if (only1_count > 0)
            print_qdir_items(only1, only1_count);
        else
            say_and_print("ничем не отличаются");

        say_and_print(" а %s ", obj2);

        if (only2_count > 0)
            print_qdir_items(only2, only2_count);
        else
            say_and_print("ничем не отличаются");

        printed = 1;
    }

    if (printed) printf("\n");
    return OK;
}

err_t akinator_write_file(akinator_t* akin, const char* filename)
{
    if (!CHECK(ERROR, akin != NULL, "akinator_write_file: akin == NULL")) return ERR_BAD_ARG;
    err_t ret = (err_t)clean_file(filename);
    if (ret != 1) return ERR_CORRUPT;
    FILE* file = load_file(filename, "wb");
    ret = tree_fprint_json(file, &(akin->tree));
    fclose(file);
    return ret;
}

static const int ru_letter_len = strlen("д");

static int ru_is_yes(const char *s) 
{
    return strncmp(s, "д",  1*ru_letter_len) == 0 || 
           strncmp(s, "Д",  1*ru_letter_len) == 0 ||
           strncmp(s, "да", 2*ru_letter_len) == 0 || 
           strncmp(s, "Да", 2*ru_letter_len) == 0 || 
           strncmp(s, "ДА", 2*ru_letter_len) == 0;
}

static int ru_is_no(const char *s) 
{
    return strncmp(s, "н",   1*ru_letter_len) == 0 || 
           strncmp(s, "Н",   1*ru_letter_len) == 0 ||
           strncmp(s, "нет", 3*ru_letter_len) == 0 || 
           strncmp(s, "Нет", 3*ru_letter_len) == 0 || 
           strncmp(s, "НЕТ", 3*ru_letter_len) == 0;
}

static int get_yes_no(const char *prompt_fmt, const char *subject)
{
    char ans[8] = { 0 };

    if (subject) say_and_print(prompt_fmt, subject);
    else         say_and_print("%s", prompt_fmt);

    if (scanf("%7s", ans) != 1) return -1;

    flush_input();

    if (ru_is_yes(ans)) return 1;
    if (ru_is_no(ans))  return 0;
    return -1;
}

static const char* ltrim_spaces(const char *s) 
{
    while (*s == ' ') s++;
    return s;
}

static void rtrim_spaces(char *s) 
{
    size_t l = strlen(s);
    while (l && s[l-1] ==' ') s[--l]='\0';
}

static void ensure_qmark(char *s, size_t cap) 
{
    size_t l = strlen(s);
    if (l==0 || s[l-1] != '?') 
    {
        if (l < cap-1) 
        { 
            s[l++]='?'; 
            s[l]='\0'; 
        } else 
        { 
            s[cap-2]='?'; 
            s[cap-1]='\0'; 
        }
    }
}

static int detect_negation(const char *s) 
{
    return strncmp(s, "не ", 2*ru_letter_len + 1) == 0 ||
           strncmp(s, "Не ", 2*ru_letter_len + 1) == 0 ||
           strncmp(s, "НЕ ", 2*ru_letter_len + 1) == 0 ||
           strstr(s, " не ") || strstr(s, " Не ") || strstr(s, " НЕ ");
}

static void normalize_predicate(const char *in, char *out, size_t cap, int *is_neg) 
{
    const char *p = ltrim_spaces(in);
    *is_neg       = detect_negation(p);

    if (*is_neg) p = p + 2*ru_letter_len + 1;

    size_t l = strlen(p);
    if (l >= cap) l = cap-1;
    memcpy(out, p, l); out[l] = '\0';
    rtrim_spaces(out);
    ensure_qmark(out, cap);
}

err_t akinator_run(akinator_t* akin)
{
    if (!CHECK(ERROR, akin != NULL && akin->tree.root != NULL,
                 "akinator_run: bad arguments")) return ERR_BAD_ARG;
    node_t* parent = NULL;
    akin->curr = akin->tree.root;

    for (;;) 
    {
        node_t* n = akin->curr;

        if (!n->left && !n->right) {
            int answer = get_yes_no("Это %s? ", n->data ? n->data : "");
            if (answer == 1) { say_and_print("Прочитан! Ты загадал %s\n", n->data); return OK; }

            char obj[512]  = { 0 };
            char pred[512] = { 0 };
            char crit[512] = { 0 };

            say_and_print("Что ты хотел чтобы я угадал: ");
            int r1 = read_line(obj, sizeof(obj));
            if (r1 < 0) return ERR_BAD_ARG;

            say_and_print("Чем \"%s\" отличается \"%s\"? \"%s\" ",
                          obj,
                          n->data ? n->data : "",
                          obj);

            int r2 = read_line(pred, sizeof(pred));
            if (r2 < 0) return ERR_BAD_ARG;

            int neg = 0;
            normalize_predicate(pred, crit, sizeof(crit), &neg);

            if (parent == NULL) 
            {
                node_t* old_root = akin->tree.root;
                node_t* q = (node_t*)calloc(1, sizeof(*q));
                if (!q) return ERR_ALLOC;

                size_t lp = strlen(crit);
                q->data = (char*)calloc(lp + 1, 1);
                if (!q->data) { free(q); return ERR_ALLOC; }

                memcpy(q->data, crit, lp);
                if (!neg) q->right = old_root; else q->left = old_root;

                akin->tree.root = q;
                akin->tree.nodes_amount += 1;
                if (!neg) 
                    { if (insert_object(akin, obj, q, DIR_YES, DIR_IGNORE) != OK) return ERR_CORRUPT; }
                else 
                    { if (insert_object(akin, obj, q, DIR_NO, DIR_IGNORE) != OK) return ERR_CORRUPT; } 
            } else
            {
                directions_e dir_enum = (parent->left == n) ? DIR_YES : DIR_NO;
                if (!neg)
                {
                    if (insert_object(akin, crit, parent, dir_enum, DIR_NO) != OK) return ERR_CORRUPT;
                    node_t* node = (dir_enum == DIR_YES) ? parent->left : parent->right;
                    if (insert_object(akin, obj, node, DIR_YES, DIR_IGNORE) != OK) return ERR_CORRUPT;
                } else
                {
                    if (insert_object(akin, crit, parent, dir_enum, DIR_YES) != OK) return ERR_CORRUPT;
                    node_t* node = (dir_enum == DIR_YES) ? parent->left : parent->right;
                    if (insert_object(akin, obj, node, DIR_NO, DIR_IGNORE) != OK) return ERR_CORRUPT;
                }
            }
            say_and_print("Спасибо, я когда-нибудь все запомню...\n");
            return OK;
        }

        
        int yn = get_yes_no("%s: ", n->data ? n->data : "");
        if (yn < 0) continue;

        parent = n;
        if (yn == 1)
            akin->curr = n->left ? n->left : n->right;
        else
            akin->curr = n->right ? n->right : n->left;
    }
}

#define NIL_CMP(buff, pos) \
    ((buff)[*(pos)] == 'n' && (buff)[*(pos)+1] == 'i' && (buff)[*(pos)+2] == 'l')

static void skip_ws(operational_data_t* op_data, size_t* pos)
{
    while (*pos < op_data->buffer_size)
    {
        char c = op_data->buffer[*pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { (*pos)++; }
        else break;
    }
}

static int match_ch(operational_data_t* op_data, size_t* pos, char ch)
{
    skip_ws(op_data, pos);
    if (*pos < op_data->buffer_size && op_data->buffer[*pos] == ch) 
        { (*pos)++; return 1; }
    return 0;
}

static size_t read_data(operational_data_t* op_data, size_t* pos, char* data)
{
    const char* buf = op_data->buffer;
    const char* p   = ltrim_spaces(&buf[*pos]);
    *pos = (size_t)(p - buf);

    const char* open = (*p == '"') ? p : strstr(p, "\"");
    if (open == NULL) return 0;
    open++;

    size_t n = 0;
    while (*open && *open != '"' && n < 511)
    {
        data[n++] = *open;
        open++;
    }
    if (*open != '"') return 0;

    data[n] = '\0';

    size_t read = (size_t)(open + 1 - p);
    *pos += read;
    return read;
}

static node_t* read_node(operational_data_t* op_data, size_t* curr_pos, logging_level level)
{
    skip_ws(op_data, curr_pos);
    if (*curr_pos >= op_data->buffer_size) return NULL;

    if (level == DEBUG) printf("\n---NEW DUMP---\n%s\n", &(op_data->buffer[*curr_pos]));

    if (op_data->buffer[*curr_pos] == '{')
    {
        node_t* node = NULL;
        err_t ret = node_ctor(&node);
        if (ret != OK) return NULL;

        (*curr_pos)++;

        char data[512] = { 0 };
        if (read_data(op_data, curr_pos, data) == 0) { tree_delete_node(node, 0); return NULL; }
        node->data = strdup(data);
        
        CREATE_TREE(tmp_tree);
        tmp_tree.root = node;
        tree_dump(&tmp_tree, "loading node...", "tg_load_dump.html");
        if (!match_ch(op_data, curr_pos, ':')) { tree_delete_node(node, 0); return NULL; }
        if (!match_ch(op_data, curr_pos, '[')) { tree_delete_node(node, 0); return NULL; }

        node->left  = read_node(op_data, curr_pos, level);
        if (!match_ch(op_data, curr_pos, ',')) { tree_delete_node(node, 0); return NULL; }
        tree_dump(&tmp_tree, "loaded left...", "tg_load_dump.html");

        node->right = read_node(op_data, curr_pos, level);
        tree_dump(&tmp_tree, "loaded both (left and right)...", "tg_load_dump.html");

        if (!match_ch(op_data, curr_pos, ']')) { tree_delete_node(node, 0); return NULL; }
        if (!match_ch(op_data, curr_pos, '}')) { tree_delete_node(node, 0); return NULL; }

        return node;
    }
    else if (op_data->buffer[*curr_pos] == '\"')
    {
        node_t* node = NULL;
        err_t ret = node_ctor(&node);
        if (ret != OK) return NULL;

        char data[512] = {0};
        if (read_data(op_data, curr_pos, data) == 0) { tree_delete_node(node, 0); return NULL; }
        node->data = strdup(data);
        return node;
    }
    else if (NIL_CMP(op_data->buffer, curr_pos))
    {
        (*curr_pos) += 4;
        return NULL;
    }

    return NULL;
}

#undef NIL_CMP

err_t akinator_read_file(akinator_t* akin, const char* filename, logging_level level)
{
    if (!CHECK(ERROR, akin != NULL, "akinator_read_file: akin == NULL")) return ERR_BAD_ARG;

    size_t fsize = (size_t)get_file_size_stat(filename) + 1;
    operational_data_t op_data = {  };
    memset(&op_data, 0, sizeof(op_data));
    op_data.buffer_size = fsize;
    op_data.buffer = (char*)calloc(1, fsize);

    FILE* file = load_file(filename, "rb");
    size_t read = read_file(file, &op_data);
    if (read == 0) return ERR_CORRUPT;

    size_t curr_pos = 0;
    if (op_data.buffer_size >= 3 &&
        (unsigned char)op_data.buffer[0] == 0xEF &&
        (unsigned char)op_data.buffer[1] == 0xBB &&
        (unsigned char)op_data.buffer[2] == 0xBF) {
        curr_pos = 3;
    }

    tree_dump_reset("tg_load_dump.html");
    tree_clear(&(akin->tree));
    akin->tree.root = read_node(&op_data, &curr_pos, level);
    if (akin->tree.root == NULL) return ERR_CORRUPT;

    free(op_data.buffer);
    fclose(file);
    return OK;
}

