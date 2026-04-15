#include "server.h"
#include "config.h"
#include "logger.h"
#include "DNSCodec.h"
#include "Filter.h"
#include "eventloop.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>

namespace dns_filter
{

std::shared_ptr<Server::ConfigSubscriberProxy> Server::subscriber_proxy_ = nullptr;

// 订阅者代理实现
void Server::ConfigSubscriberProxy::update(const std::string& key)
{
    Server::get_server().on_config_update(key);
}

Server::Server() : running_(false), event_loop_started_(false), timeout_ms_(2000), upstream_addr_valid_(false)
{
    auto upstream = Configer::get_configer().upstream_dns();
    upstream_dns_ = upstream.value_or("8.8.8.8:53");

    auto upstream_secondary = Configer::get_configer().upstream_dns_secondary();
    upstream_dns_secondary_ = upstream_secondary.value_or("1.1.1.1:53");

    auto timeout = Configer::get_configer().timeout_ms();
    timeout_ms_ = timeout.value_or(2000);

    // 初始化上游地址
    if (init_upstream_addr(upstream_dns_, upstream_addr_))
    {
        upstream_addr_valid_ = true;
    }
    init_upstream_addr(upstream_dns_secondary_, upstream_addr_secondary_);
}

Server::~Server()
{
    stop();
}

Server& Server::get_server()
{
    static Server server;
    return server;
}

void Server::on_config_update(const std::string& key)
{
    if (key == "server")
    {
        // server 下任意字段变更，统一重新读取所有配置
        auto upstream = Configer::get_configer().upstream_dns();
        if (upstream.has_value())
        {
            upstream_dns_ = upstream.value();
            if (init_upstream_addr(upstream_dns_, upstream_addr_))
            {
                upstream_addr_valid_ = true;
            }
            Logger::info("上游DNS已更新: " + upstream_dns_);
        }

        auto upstream_secondary = Configer::get_configer().upstream_dns_secondary();
        if (upstream_secondary.has_value())
        {
            upstream_dns_secondary_ = upstream_secondary.value();
            init_upstream_addr(upstream_dns_secondary_, upstream_addr_secondary_);
            Logger::info("备用上游DNS已更新: " + upstream_dns_secondary_);
        }

        auto timeout = Configer::get_configer().timeout_ms();
        if (timeout.has_value())
        {
            timeout_ms_ = timeout.value();
            Logger::info("超时时间已更新: " + std::to_string(timeout_ms_) + "ms");
        }
    }
}

void Server::start()
{
    if (running_)
    {
        Logger::warn("Server已在运行中");
        return;
    }

    Logger::info("DNS Filter 启动中...");

    // 注册配置订阅（订阅顶层 key "server"，其下任意字段变更都会通知）
    if (!subscriber_proxy_)
    {
        subscriber_proxy_ = std::make_shared<ConfigSubscriberProxy>();
        Configer::get_configer().subscribe("server", subscriber_proxy_);
    }

    running_ = true;
    EventLoop::get_EventLoop();
    event_loop_started_ = true;
    EventLoop::get_EventLoop().loop();

    Logger::info("DNS Filter 已停止");
}

void Server::stop()
{
    if (!running_)
        return;

    running_ = false;
    if (!event_loop_started_)
        return;

    EventLoop::get_EventLoop().stop();
}

void Server::handle_query(const std::vector<uint8_t>& data,
                          const struct sockaddr_in& client_addr)
{
    // 清理过期的查询
    cleanup_expired_queries();

    // 获取 Transaction ID
    uint16_t txid = DNSCodec::get_transaction_id(data);

    // 1. 检查是否需要解码处理
    if (!DNSCodec::does_need_decoding(data))
    {
        // 非 A/AAAA 查询，直接转发
        // 保存映射
        pending_queries_[txid] = {client_addr, std::chrono::steady_clock::now()};
        forward_to_upstream(data);
        return;
    }

    // 2. 解析域名
    auto domain_opt = DNSCodec::parse_query_name(data);
    if (!domain_opt.has_value())
    {
        Logger::warn("域名解析失败，丢弃该查询");
        return;
    }

    const std::string& domain = domain_opt.value();
    Logger::info("收到查询: " + domain);

    // 3. 过滤判断
    if (Filter::get_filter().is_ads(domain))
    {
        Logger::info("拦截域名: " + domain);

        auto block_response = DNSCodec::build_block_response(data);
        if (block_response.has_value())
        {
            EventLoop::get_EventLoop().send_dns(
                std::string(block_response->begin(), block_response->end()),
                client_addr);
        }
        return;
    }

    // 4. 转发到上游（异步）
    pending_queries_[txid] = {client_addr, std::chrono::steady_clock::now()};
    forward_to_upstream(data);
}

bool Server::parse_upstream_addr(const std::string& addr_str,
                                 std::string& ip, uint16_t& port)
{
    size_t colon_pos = addr_str.find(':');
    if (colon_pos == std::string::npos)
    {
        ip = addr_str;
        port = 53;
        return true;
    }

    ip = addr_str.substr(0, colon_pos);
    try
    {
        port = static_cast<uint16_t>(std::stoi(addr_str.substr(colon_pos + 1)));
    }
    catch (...)
    {
        Logger::error("解析上游地址端口失败: " + addr_str);
        return false;
    }

    return true;
}

bool Server::forward_to_upstream(const std::vector<uint8_t>& query)
{
    if (!upstream_addr_valid_)
    {
        Logger::error("上游地址未初始化");
        return false;
    }

    // 使用 EventLoop 的监听 socket 发送
    ssize_t sent = EventLoop::get_EventLoop().send_to_upstream(
        std::string(query.begin(), query.end()), upstream_addr_);

    if (sent < 0)
    {
        Logger::error(std::string("发送到上游DNS (") + upstream_dns_ + ") 失败: " + std::strerror(errno));

        // 尝试备用上游
        if (!upstream_dns_secondary_.empty())
        {
            return forward_to_upstream_secondary(query);
        }
        return false;
    }

    Logger::debug("查询已转发到上游: " + upstream_dns_);
    return true;
}

bool Server::forward_to_upstream_secondary(const std::vector<uint8_t>& query)
{
    Logger::info("尝试备用上游DNS: " + upstream_dns_secondary_);

    ssize_t sent = EventLoop::get_EventLoop().send_to_upstream(
        std::string(query.begin(), query.end()), upstream_addr_secondary_);

    if (sent < 0)
    {
        Logger::error(std::string("发送到备用上游DNS (") + upstream_dns_secondary_ + ") 失败: " + std::strerror(errno));
        return false;
    }

    Logger::info("查询已转发到备用上游");
    return true;
}

bool Server::init_upstream_addr(const std::string& addr_str, struct sockaddr_in& addr)
{
    std::string ip;
    uint16_t port;
    if (!parse_upstream_addr(addr_str, ip, port))
    {
        return false;
    }

    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        Logger::error("无效的上游IP地址: " + ip);
        return false;
    }

    return true;
}

void Server::handle_upstream_response(const std::vector<uint8_t>& data,
                                      const struct sockaddr_in& upstream_addr)
{
    // 获取 Transaction ID
    uint16_t txid = DNSCodec::get_transaction_id(data);

    // 查找对应的客户端
    auto it = pending_queries_.find(txid);
    if (it == pending_queries_.end())
    {
        Logger::warn("收到未知 Transaction ID 的响应: " + std::to_string(txid));
        return;
    }

    // 发送给客户端
    EventLoop::get_EventLoop().send_dns(
        std::string(data.begin(), data.end()),
        it->second.client_addr);

    // 移除映射
    pending_queries_.erase(it);

    Logger::debug("上游响应已转发给客户端");
}

void Server::cleanup_expired_queries()
{
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::milliseconds(timeout_ms_);

    for (auto it = pending_queries_.begin(); it != pending_queries_.end(); )
    {
        if (now - it->second.timestamp > timeout)
        {
            Logger::warn("查询超时，Transaction ID: " + std::to_string(it->first));
            it = pending_queries_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

}
