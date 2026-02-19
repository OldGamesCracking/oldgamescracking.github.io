#include <stdio.h>
#include <stdarg.h>
#include "logging.h"


/* Global Logging object, shared by all modules */
Logging logger;


Logging::Logging()
{
    this->fp_Log = fopen("worker_log.txt", "a");
}

Logging::~Logging()
{
    if (this->fp_Log == NULL)
    {
        return;
    }

    fclose(this->fp_Log);

    this->fp_Log = NULL;
}

void Logging::Log(const char* format, ...)
{
    if (this->fp_Log == NULL)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    vfprintf(this->fp_Log, format, args);
    fflush(this->fp_Log);

    va_end(args);
}

void Logging::LogLine(const char *format, ...)
{
    if (this->fp_Log == NULL)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    vfprintf(this->fp_Log, format, args);
    fprintf(this->fp_Log, "\n");
    fflush(this->fp_Log);

    va_end(args);
}
