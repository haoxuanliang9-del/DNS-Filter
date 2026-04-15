#pragma once

#include <iostream>
#include <string>
#include <memory>
#include "configsubscriber.h"
#include <unordered_set>


namespace dns_filter
{

class Filter
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

    void on_config_update(const std::string &key);
    bool is_ads(const std::string &domain) const;

private:

    std::unordered_set<std::string> blacklist_;
    std::unordered_set<std::string> whitelist_;

    bool whitelist_enabled_ = false;

    std::string rule_dir_;

    Filter();

    // 订阅者代理
    class ConfigSubscriberProxy : public ConfigSubscriber
    {
    public:
        void update(const std::string& key) override;
    };
    static std::shared_ptr<ConfigSubscriberProxy> subscriber_proxy_;

    void load_list(const std::string &file_path, std::unordered_set<std::string> &list);

};

}
