#pragma once

#include <vector>
#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <memory>
#include <unordered_map>
#include <chrono>
#include "configsubscriber.h"

namespace dns_filter
{

class Server
{
public:
    static Server& get_server();

    void start();
    void stop();

    void handle_query(const std::vector<uint8_t>& data,
                      const struct sockaddr_in& client_addr);

    void handle_upstream_response(const std::vector<uint8_t>& data,
                                  const struct sockaddr_in& upstream_addr);

    void on_config_update(const std::string& key);

private:
    Server();
    ~Server();

    bool running_;
    bool event_loop_started_;

    std::string upstream_dns_;
    std::string upstream_dns_secondary_;
    int timeout_ms_;

    // 上游地址（用于判断来源）
    struct sockaddr_in upstream_addr_;
    struct sockaddr_in upstream_addr_secondary_;
    bool upstream_addr_valid_;

    // Transaction ID -> 客户端地址映射
    struct PendingQuery
    {
        sockaddr_in client_addr;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<uint16_t, PendingQuery> pending_queries_;

    // 订阅者代理
    class ConfigSubscriberProxy : public ConfigSubscriber
    {
    public:
        void update(const std::string& key) override;
    };
    static std::shared_ptr<ConfigSubscriberProxy> subscriber_proxy_;

    bool forward_to_upstream(const std::vector<uint8_t>& query);
    bool forward_to_upstream_secondary(const std::vector<uint8_t>& query);

    bool parse_upstream_addr(const std::string& addr_str,
                             std::string& ip, uint16_t& port);
    bool init_upstream_addr(const std::string& addr_str, struct sockaddr_in& addr);

    void cleanup_expired_queries();
};

}
