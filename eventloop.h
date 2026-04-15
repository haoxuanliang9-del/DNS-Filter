#pragma once

#include <iostream>
#include <string>
#include <netinet/in.h>
#include <memory>
#include "configsubscriber.h"

namespace dns_filter
{
class EventLoop
{
public:
    static EventLoop &get_EventLoop()
    {
        static EventLoop EventLoop;
        return EventLoop;
    }

    void on_config_update(const std::string &key);

    void send_dns(const std::string &data, const struct sockaddr_in &client_addr);
    ssize_t send_to_upstream(const std::string &data, const struct sockaddr_in &upstream_addr);
    void loop();
    void stop();

private:
    EventLoop();
    ~EventLoop();

    int socket_fd_;
    bool running_;
    bool restart_requested_;

    int set_nonblocking(int fd);

    // 订阅者代理
    class ConfigSubscriberProxy : public ConfigSubscriber
    {
    public:
        void update(const std::string& key) override;
    };
    static std::shared_ptr<ConfigSubscriberProxy> subscriber_proxy_;
};
}
