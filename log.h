#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <stdarg.h>

#define DEBUG 1
#define INFO 2
#define WARN 3
#define ERROR 4
#define FATAL 5

char log_level;

void logger(char level, char *fmt, ...);