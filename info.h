#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define DOMAIN "075786.cn"

void process_req(char *buf);
void process_res(char *buf);