#pragma once

#include <cstdio>
#include <cstdarg>


class Logging
{
private:
    FILE *File = nullptr;

public:
    Logging()
    {
        if (fopen_s(&File, "worker_log.txt", "a") != NULL)
        {
            File = nullptr;
        }
    }

    ~Logging()
    {
        if (File == nullptr)
        {
            return;
        }

        fclose(File);

        File = nullptr;
    }

    template <class ... Args>
    void Log(const char *format, Args ... args)
    {
        if (File == nullptr)
        {
            return;
        }

        fprintf(File, format, args...);
        fflush(File);
    }

    template <class ... Args>
    void Line(const char *format, Args ... args)
    {
        Log(format, args...);
        Log("\n");
    }

    template <class ... Args>
    void LogPrefix(const char *prefix, const char *format, Args ... args)
    {
        Log(prefix);
        Line(format, args...);
    }

    template <class ... Args>
    void Debug(const char *format, Args ... args)
    {
        if (Verbose)
        {
            Line(format, args...);
        }
    }

    template <class ... Args>
    void Warning(const char *format, Args ... args)
    {
        LogPrefix("[WARNING] ", format, args...);
    }

    template <class ... Args>
    void Error(const char *format, Args ... args)
    {
        LogPrefix("[ERROR] ", format, args...);
    }

    bool Verbose = false;
};

extern Logging Log;