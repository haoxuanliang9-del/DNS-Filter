#pragma once

#include <iostream>
#include <string>
#include "configsubscriber.h"
#include <unordered_set>


namespace dns_filter
{

class Filter : public ConfigSubscriber
{
public:
    Filter(const Filter &) = delete;
    Filter(Filter &&) = delete;
    Filter &operator=(const Filter &) = delete;
    Filter &operator=(Filter &&) = delete;

    static Filter &get_filter()
    {
        static Filter filter;
        return filter;
    }

    void update(const std::string &key);
    bool is_ads(const std::string &domain) const;

private:

    std::unordered_set<std::string> blacklist_;
    std::unordered_set<std::string> whitelist_;

    bool whitelist_enabled_ = false;

    std::string rule_dir_;

    Filter();

    

    void load_list(const std::string &file_path, std::unordered_set<std::string> &list);

};

}
