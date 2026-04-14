#pragma once

#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <cctype>
#include <optional>
#include <map>
#include <vector>
#include <memory>
#include <algorithm>
#include "configsubscriber.h"
#include <pthread.h>

namespace dns_filter
{

class Configer
{

public:
    
    Configer(const Configer&) = delete;
    Configer(Configer&&) = delete;
    Configer &operator=(const Configer &) = delete;
    Configer &operator=(Configer &&) = delete;

    static Configer& get_configer()
    {
        static Configer config;
        return config;
    }

    void config_init();
    void config_reload(const nlohmann::json &new_config);

    void subscribe(const std::string &key, std::shared_ptr<ConfigSubscriber> subscriber);

    void unsubscribe(const std::string &key, std::shared_ptr<ConfigSubscriber> subscriber);



    // 获取配置项接口，返回 optional 以区分缺失/类型错误
    // server 配置（返回 optional，调用者可自行判断缺失/类型错误）
    std::optional<std::string> listen_addr() const;
    std::optional<int> listen_port() const;
    std::optional<std::string> upstream_dns() const;
    std::optional<std::string> upstream_dns_secondary() const;
    std::optional<int> timeout_ms() const;
    // filter 配置
    std::optional<std::string> rule_file() const;
    std::optional<bool> whitelist_enabled() const;
    // logging 配置
    std::optional<std::string> logging_level() const;
    std::optional<std::string> logging_file() const;
    std::optional<int> logging_max_size_mb() const;
    std::optional<int> logging_max_files() const;
    // gui 配置
    std::optional<bool> gui_enabled() const;
    std::optional<int> http_api_port() const;



private:
    Configer();


    nlohmann::json config_json_;

    std::map<std::string, std::vector<std::weak_ptr<ConfigSubscriber>>> subscribers_;

    pthread_mutex_t mutex_;




    bool config_valid(const nlohmann::json &config);

    static nlohmann::json default_config();

    bool is_valid_ipv4(const std::string &ip);
};



}