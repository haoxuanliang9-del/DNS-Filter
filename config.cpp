#include "config.h"
#include <stdexcept>


namespace dns_filter
{

Configer::Configer()
{
    pthread_mutex_init(&mutex_, NULL);
    config_init();
}

void Configer::subscribe(const std::string &key, std::shared_ptr<ConfigSubscriber> subscriber)
{
    pthread_mutex_lock(&mutex_);
    subscribers_[key].push_back(subscriber);
    pthread_mutex_unlock(&mutex_);
}

void Configer::unsubscribe(const std::string &key, std::shared_ptr<ConfigSubscriber> subscriber)
{
    pthread_mutex_lock(&mutex_);
    auto it = subscribers_.find(key);
    if (it != subscribers_.end())
    {
        auto &vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(), [&subscriber](const std::weak_ptr<ConfigSubscriber> &item) {
                      return item.lock() == subscriber;
                  }),
                  vec.end());
    }
    pthread_mutex_unlock(&mutex_);
}


void Configer::config_init()
{
    std::ifstream in("config.json");
    nlohmann::json defaults = default_config();
    if (!in)
    {
        std::cerr << "无法打开配置文件，启用默认配置!\n";
        config_json_ = defaults;
    }
    else
    {
        try
        {
            nlohmann::json j;
            in >> j;
            defaults.merge_patch(j);
            config_json_ = defaults;
        }
        catch (const nlohmann::json::parse_error &e)
        {
            std::cerr << "解析配置文件失败：" << e.what() << "，启用默认配置！" << '\n';
            config_json_ = defaults;
        }
    }

    if (!config_valid(config_json_))
    {
        config_json_ = defaults;
        std::cerr << "配置错误，启用默认配置！" << '\n';
    }
}

void Configer::config_reload(const nlohmann::json &new_config)
{
    nlohmann::json old_config = config_json_;

    nlohmann::json merged_config = old_config;
    merged_config.merge_patch(new_config);

    if (!config_valid(merged_config))
    {
        std::cerr << "配置错误，已回滚！" << '\n';
    }
    else
    {
        pthread_mutex_lock(&mutex_);
        config_json_ = merged_config;
        pthread_mutex_unlock(&mutex_);
        nlohmann::json patch = nlohmann::json::diff(old_config, config_json_);
        for (const auto &op : patch)
        {
            if (op.value("op", "") == "replace")
            {
                std::string key = op.value("path", "").substr(1); // 去掉开头的 '/'
                if (key.empty())
                {
                    continue;
                }

                std::string key1 = key.substr(0, key.find('/'));
                std::vector<std::shared_ptr<ConfigSubscriber>> subscribers;
                {
                    pthread_mutex_lock(&mutex_);
                    auto it = subscribers_.find(key1);
                    if (it != subscribers_.end())
                    {
                        for (const auto &subscriber : it->second)
                        {
                            if (auto ptr = subscriber.lock())
                            {
                                subscribers.push_back(ptr);
                            }
                        }
                    }
                    pthread_mutex_unlock(&mutex_);
                }

                for (auto &subscriber : subscribers)
                {
                    subscriber->update(key1);
                }
            }
        }
    }
}

bool Configer::config_valid(const nlohmann::json &config)
{
    try
    {
        int port = config.at("server").at("listen_port").get<int>();
        const auto &server = config.at("server");
        std::string ip;
        if (server.contains("listen_addr"))
        {
            ip = server.at("listen_addr").get<std::string>();
        }
        else
        {
            ip = server.at("listen_address").get<std::string>();
        }
        if(port<1 || port>65535)
            throw std::out_of_range("端口号超出范围");
        if (!is_valid_ipv4(ip))
            throw std::invalid_argument("ip地址格式错误");
    }
    catch (const nlohmann::json::exception &e)
    {
        std::cerr << "ip/端口缺失或格式错误：" << e.what() << "!\n";
        return false;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
        return true;
        
}

    // Definitions moved from header
    std::optional<std::string> Configer::listen_addr() const
    {
        auto it = config_json_.find("server");
        if (it == config_json_.end() || !it->is_object())
            return std::nullopt;
        const auto &srv = *it;

        auto it2 = srv.find("listen_address");
        if (it2 != srv.end() && it2->is_string())
            return it2->get<std::string>();

        it2 = srv.find("listen_addr");
        if (it2 != srv.end() && it2->is_string())
            return it2->get<std::string>();

        return std::nullopt;
    }

    std::optional<int> Configer::listen_port() const
    {
        auto it = config_json_.find("server");
        if (it == config_json_.end() || !it->is_object())
            return std::nullopt;
        const auto &srv = *it;
        auto it2 = srv.find("listen_port");
        if (it2 == srv.end() || !it2->is_number_integer())
            return std::nullopt;
        return it2->get<int>();
    }

    std::optional<std::string> Configer::upstream_dns() const
    {
        auto it = config_json_.find("server");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &srv = *it;
        auto it2 = srv.find("upstream_dns");
        if (it2 == srv.end() || !it2->is_string()) return std::nullopt;
        return it2->get<std::string>();
    }

    std::optional<std::string> Configer::upstream_dns_secondary() const
    {
        auto it = config_json_.find("server");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &srv = *it;
        auto it2 = srv.find("upstream_dns_secondary");
        if (it2 == srv.end() || !it2->is_string()) return std::nullopt;
        return it2->get<std::string>();
    }

    std::optional<int> Configer::timeout_ms() const
    {
        auto it = config_json_.find("server");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &srv = *it;
        auto it2 = srv.find("timeout_ms");
        if (it2 == srv.end() || !it2->is_number_integer()) return std::nullopt;
        return it2->get<int>();
    }


    std::optional<std::string> Configer::rule_file() const
    {
        auto it = config_json_.find("filter");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &f = *it;
        auto it2 = f.find("rule_file");
        if (it2 == f.end() || !it2->is_string()) return std::nullopt;
        return it2->get<std::string>();
    }

    std::optional<bool> Configer::whitelist_enabled() const
    {
        auto it = config_json_.find("filter");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &f = *it;
        auto it2 = f.find("whitelist_enabled");
        if (it2 == f.end() || !it2->is_boolean()) return std::nullopt;
        return it2->get<bool>();
    }

    std::optional<std::string> Configer::logging_level() const
    {
        auto it = config_json_.find("logging");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &l = *it;
        auto it2 = l.find("level");
        if (it2 == l.end() || !it2->is_string()) return std::nullopt;
        return it2->get<std::string>();
    }

    std::optional<std::string> Configer::logging_file() const
    {
        auto it = config_json_.find("logging");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &l = *it;
        auto it2 = l.find("file");
        if (it2 == l.end() || !it2->is_string()) return std::nullopt;
        return it2->get<std::string>();
    }

    std::optional<int> Configer::logging_max_size_mb() const
    {
        auto it = config_json_.find("logging");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &l = *it;
        auto it2 = l.find("max_size_mb");
        if (it2 == l.end() || !it2->is_number_integer()) return std::nullopt;
        return it2->get<int>();
    }

    std::optional<int> Configer::logging_max_files() const
    {
        auto it = config_json_.find("logging");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &l = *it;
        auto it2 = l.find("max_files");
        if (it2 == l.end() || !it2->is_number_integer()) return std::nullopt;
        return it2->get<int>();
    }

    std::optional<bool> Configer::gui_enabled() const
    {
        auto it = config_json_.find("gui");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &g = *it;
        auto it2 = g.find("enabled");
        if (it2 == g.end() || !it2->is_boolean()) return std::nullopt;
        return it2->get<bool>();
    }

    std::optional<int> Configer::http_api_port() const
    {
        auto it = config_json_.find("gui");
        if (it == config_json_.end() || !it->is_object()) return std::nullopt;
        const auto &g = *it;
        auto it2 = g.find("http_api_port");
        if (it2 == g.end() || !it2->is_number_integer()) return std::nullopt;
        return it2->get<int>();
    }

    // default_config and is_valid_ipv4 definitions
    nlohmann::json Configer::default_config()
    {
        return nlohmann::json{
            {"server", {{"listen_address", "0.0.0.0"}, {"listen_port", 5353}, {"upstream_dns", "8.8.8.8:53"}, {"upstream_dns_secondary", "1.1.1.1:53"}, {"timeout_ms", 2000}}},
            {"filter", {{"enabled", true}, {"rule_file", "config/filter_rules.json"}, {"default_action", "pass"}}},
            {"logging", {{"level", "info"}, {"file", "logs/dns_filter.log"}, {"max_size_mb", 10}, {"max_files", 5}}},
            {"gui", {{"enabled", true}, {"http_api_port", 8080}}}
        };
    }

    bool Configer::is_valid_ipv4(const std::string &ip)
    {
        if (ip.empty()) return false;
        std::istringstream ss(ip);
        std::string part;
        int count = 0;
        while (std::getline(ss, part, '.')) {
            ++count;
            if (part.empty() || part.size() > 3) return false;
            for (char c : part) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
            if (part.size() > 1 && part[0] == '0') return false;
            int val = 0;
            try { val = std::stoi(part); }
            catch (...) { return false; }
            if (val < 0 || val > 255) return false;
        }
        return count == 4;
    }



}