#ifndef TDUMP_H
#define TDUMP_H

#include "../tree.h"
#include "../../libs/logging/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

void tree_dump_reset(const char* html_file);

void tree_dump(const tree_t* tree, const char* title, const char* html_file);

#endif
