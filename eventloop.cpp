#include "eventloop.h"
#include "config.h"
#include "logger.h"
#include "server.h"
#include "DNSCodec.h"
#include <stdexcept>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>

namespace dns_filter
{

std::shared_ptr<EventLoop::ConfigSubscriberProxy> EventLoop::subscriber_proxy_ = nullptr;

// 订阅者代理实现
void EventLoop::ConfigSubscriberProxy::update(const std::string& key)
{
    EventLoop::get_EventLoop().on_config_update(key);
}

EventLoop::EventLoop() : socket_fd_(-1), running_(false), restart_requested_(false)
{
    // 注册配置订阅（订阅顶层 key "server"，其下任意字段变更都会通知）
    if (!subscriber_proxy_)
    {
        subscriber_proxy_ = std::make_shared<ConfigSubscriberProxy>();
        Configer::get_configer().subscribe("server", subscriber_proxy_);
    }

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0)
    {
        Logger::error("创建监听套接字失败");
        throw std::runtime_error("事件循环启动失败");
    }

    if (set_nonblocking(socket_fd_) != 0)
    {
        Logger::warn("设置套接字为非阻塞失败");
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(Configer::get_configer().listen_port().value_or(53));
    std::string listen_ip = Configer::get_configer().listen_addr().value_or("0.0.0.0");
    inet_pton(AF_INET, listen_ip.c_str(), &addr.sin_addr);

    if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        Logger::error(std::string("绑定监听地址失败: ") + std::strerror(errno));
        throw std::runtime_error("事件循环启动失败");
    }

}

EventLoop::~EventLoop()
{
    stop();
    if (socket_fd_ >= 0)
    {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

void EventLoop::stop()
{
    running_ = false;
}

void EventLoop::on_config_update(const std::string &key)
{
    if (key == "server")
    {
        // server 下任意字段变更，标记需要重启绑定
        restart_requested_ = true;
    }
}


void EventLoop::loop()
{
    running_ = true;
    struct pollfd fd[1];
    fd[0].fd = socket_fd_;
    fd[0].events = POLLIN;

    while (running_)
    {
        int ret = poll(fd, 1, 1000); // 1秒超时，允许检查running_和restart_requested_
        
        if (!running_)
            break;
            
        if (restart_requested_)
        {
            restart_requested_ = false;
            // 简单重绑定逻辑
            close(socket_fd_);
            socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
            if (socket_fd_ < 0)
            {
                Logger::error("重新创建套接字失败");
                break;
            }
            set_nonblocking(socket_fd_);

            struct sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(Configer::get_configer().listen_port().value_or(53));
            std::string listen_ip = Configer::get_configer().listen_addr().value_or("0.0.0.0");
            inet_pton(AF_INET, listen_ip.c_str(), &addr.sin_addr);

            if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            {
                Logger::error(std::string("重新绑定监听地址失败: ") + std::strerror(errno));
                break;
            }
            fd[0].fd = socket_fd_;
            Logger::info("套接字已重新绑定");
            continue;
        }

        if (ret > 0 && (fd[0].revents & POLLIN))
        {
            char buffer[512];
            struct sockaddr_in from_addr;
            socklen_t plen = sizeof(from_addr);
            ssize_t count = recvfrom(socket_fd_, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &plen);
            if (count > 0)
            {
                std::vector<uint8_t> data(buffer, buffer + count);

                // 判断是响应还是查询
                if (DNSCodec::is_response(data))
                {
                    // 上游响应
                    Server::get_server().handle_upstream_response(data, from_addr);
                }
                else
                {
                    // 客户端请求
                    Server::get_server().handle_query(data, from_addr);
                }
            }
        }
    }
}

void EventLoop::send_dns(const std::string &data, const struct sockaddr_in &client_addr)
{
    ssize_t count = sendto(socket_fd_, data.data(), data.size(), 0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    if (count == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            Logger::warn("一个报文因内核发送缓冲区不足发送失败");
            // 若需可靠发送，应把 data 拷贝入队并在 POLLOUT 时重试
        }
        else
        {
            Logger::error("sendto 发送失败");
        }
    }
}

ssize_t EventLoop::send_to_upstream(const std::string &data, const struct sockaddr_in &upstream_addr)
{
    return sendto(socket_fd_, data.data(), data.size(), 0, (const struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
}

int EventLoop::set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;
    return 0;
}

}