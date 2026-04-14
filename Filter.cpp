#include "Filter.h"
#include "config.h"
#include "logger.h"
#include <optional>
#include <fstream>



namespace dns_filter
{

Filter::Filter()
{
    if(Configer::get_configer().whitelist_enabled().value_or(false))
    {
        Logger::info("启用白名单");
        whitelist_enabled_ = true;
    }

    auto dir = Configer::get_configer().rule_file();
    try
    {
        rule_dir_ = dir.value();
    }
    catch (const std::exception &e)
    {
        Logger::error("无规则文件");
        throw std::runtime_error("无规则文件");
        return;
    }

    load_list(rule_dir_ + "/blacklist.txt", blacklist_);
    if(whitelist_enabled_)
    {
        load_list(rule_dir_ + "/whitelist.txt", whitelist_);
    }
}


void Filter::load_list(const std::string &file_path, std::unordered_set<std::string> &list)
{
    
    std::ifstream in(file_path);
    if (!in)
    {
        Logger::error("无法打开黑/白名单文件");
        throw std::runtime_error("无法打开黑/白名单文件");
        return;
    }
    std::string domain;
    while (std::getline(in, domain))
    {
        if (domain.size() < 2)
            continue;

        if (domain.substr(0, 2) != "||")
            continue;

        domain.erase(0, 2);

        if (domain.size() < 1)
            continue;

        if (domain.back() == '^')
            domain.pop_back();

        list.insert(domain);
    }
}

bool Filter::is_ads(const std::string &domain) const
{
    if(whitelist_enabled_)
    {
        if(whitelist_.find(domain) != whitelist_.end())
            return false;
    }

    return blacklist_.find(domain) != blacklist_.end();
}

void Filter::update(const std::string &key)
{
    if (key == "whitelist_enabled")
    {
        if(Configer::get_configer().whitelist_enabled().value_or(false))
        {
            if(whitelist_enabled_)
            {
                Logger::info("白名单已经启动，无需重复启用");
            }
            else
            {
                Logger::info("启用白名单");
                whitelist_enabled_ = true;
                load_list(rule_dir_ + "/whitelist.txt", whitelist_);
            }
        }
        else
        {
            if (whitelist_enabled_)
            {
                Logger::info("禁用白名单");
                whitelist_enabled_ = false;
                whitelist_.clear();
            }
            else
            {
                Logger::info("白名单已禁用，无需重复禁用");
            }
        }
    }


}
}