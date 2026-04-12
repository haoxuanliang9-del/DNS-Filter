#pragma once

#include <string>

class ConfigSubscriber
{
public:
    virtual void update(const std::string &key) = 0;
};