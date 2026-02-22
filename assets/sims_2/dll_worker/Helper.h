#pragma once
#include <string>
#include <cctype>    // std::tolower
#include <algorithm> // std::equal


bool ichar_equals(char a, char b)
{
    return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
}


bool iequals(const std::string &a, const std::string &b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), ichar_equals);
}