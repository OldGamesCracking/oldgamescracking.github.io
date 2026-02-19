#pragma once

#include <stdio.h>
#include <stdarg.h>


class Logging
{
    private:
        FILE *fp_Log = NULL;

    public:
        Logging();
        ~Logging();
        void Log(const char* format, ...);
        void LogLine(const char *format, ...);
};


extern Logging logger;