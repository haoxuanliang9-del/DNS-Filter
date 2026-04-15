#include "Filter.h"
#include "config.h"
#include "logger.h"
#include <optional>
#include <fstream>



namespace dns_filter
{

std::shared_ptr<Filter::ConfigSubscriberProxy> Filter::subscriber_proxy_ = nullptr;

// 订阅者代理实现
void Filter::ConfigSubscriberProxy::update(const std::string& key)
{
    Filter::get_filter().on_config_update(key);
}

Filter::Filter()
{
    // 注册配置订阅（订阅顶层 key "filter"，其下任意字段变更都会通知）
    if (!subscriber_proxy_)
    {
        subscriber_proxy_ = std::make_shared<ConfigSubscriberProxy>();
        Configer::get_configer().subscribe("filter", subscriber_proxy_);
    }

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

void Filter::on_config_update(const std::string &key)
{
    if (key == "filter")
    {
        // filter 下任意字段变更，统一重新读取配置
        auto enabled = Configer::get_configer().whitelist_enabled();
        if (enabled.has_value() && enabled.value())
        {
            if (!whitelist_enabled_)
            {
                Logger::info("启用白名单");
                try
                {
                    load_list(rule_dir_ + "/whitelist.txt", whitelist_);
                }
                catch (const std::exception &e)
                {
                    Logger::error("无法加载白名单文件");
                    return;
                }
                whitelist_enabled_ = true;
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
        }

        // 规则文件路径变更时重新加载黑名单
        auto dir = Configer::get_configer().rule_file();
        if (dir.has_value() && dir.value() != rule_dir_)
        {
            rule_dir_ = dir.value();
            blacklist_.clear();
            load_list(rule_dir_ + "/blacklist.txt", blacklist_);
            if (whitelist_enabled_)
            {
                whitelist_.clear();
                load_list(rule_dir_ + "/whitelist.txt", whitelist_);
            }
            Logger::info("规则文件路径已更新，重新加载: " + rule_dir_);
        }
    }
}
}