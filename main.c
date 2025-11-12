#include "akinator/akinator.h"
#include "libs/logging/logging.h"

#include "tree/dump/dump.h"

int main()
{
    init_logging("log.log", DEBUG);

    CREATE_AKINATOR(akinator1);

    akinator_read_file(&akinator1, "akinator1_db");
    tree_dump(akinator1.tree, "test", "tgdump.html");

    /*
    insert_object(&akinator1, "Животное?", NULL, DIR_IGNORE, DIR_IGNORE);
    tree_dump(akinator1.tree, "test", "tgdump.html");
    node_t* root = akinator1.tree->root;

    insert_object(&akinator1, "Полторашка", root, DIR_YES, DIR_IGNORE);
    insert_object(&akinator1, "Препает матан?", root, DIR_NO, DIR_IGNORE);
    tree_dump(akinator1.tree, "test", "tgdump.html");

    node_t* preps = root->right;

    insert_object(&akinator1, "ПетроВич", preps, DIR_YES, DIR_IGNORE);
    tree_dump(akinator1.tree, "test", "tgdump.html");

    insert_object(&akinator1, "Паша", preps, DIR_NO, DIR_IGNORE);
    tree_dump(akinator1.tree, "test", "tgdump.html"); 

    insert_object(&akinator1, "Задает домашки?", preps, DIR_NO, DIR_NO);
    node_t* gives = preps->right;
    insert_object(&akinator1, "Кириков", gives, DIR_YES, DIR_IGNORE);
    tree_dump(akinator1.tree, "test", "tgdump.html"); 

    akinator_run(&akinator1);
    tree_dump(akinator1.tree, "test", "tgdump.html"); 
    */

    //akinator_write_file(&akinator1, "akinator1_db");

    akinator_dtor(&akinator1);

    close_log_file();

    return 0;
}
