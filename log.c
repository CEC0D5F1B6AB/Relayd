#include "log.h"

void logger(char level, char *fmt, ...)
{
	if (level != DEBUG)
		return;

	va_list argp;
	va_start(argp, fmt);
	va_end(argp);
	vfprintf(stdout, fmt, argp);
	return;
}