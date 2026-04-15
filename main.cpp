#include "config.h"
#include "logger.h"
#include "server.h"
#include "Filter.h"
#include <csignal>
#include <cstdlib>
#include <exception>
#include <thread>
#include <chrono>

namespace
{
volatile std::sig_atomic_t signal_received = 0;

void signal_handler(int signal)
{
    signal_received = signal;
}
}

int main()
{
    try
    {
        // 1. 初始化配置
        dns_filter::Configer::get_configer().config_init();

        // 2. 初始化日志
        dns_filter::Logger::init();

        // 3. 初始化过滤器（加载黑白名单）
        dns_filter::Filter::get_filter();

        // 4. 注册信号处理
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        dns_filter::Logger::info("DNS Filter 主程序启动");

        // 5. 启动服务（放入独立线程，避免阻塞主线程的信号处理）
        std::thread server_thread([]()
        {
            try
            {
                dns_filter::Server::get_server().start();
            }
            catch (const std::exception& e)
            {
                dns_filter::Logger::error(std::string("服务启动失败: ") + e.what());
                signal_received = SIGTERM;
            }
        });

        // 6. 等待信号
        while (!signal_received)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        dns_filter::Logger::info("收到信号，准备退出...");

        // 7. 停止服务
        dns_filter::Server::get_server().stop();

        if (server_thread.joinable())
        {
            server_thread.join();
        }

        // 8. 关闭日志
        dns_filter::Logger::shutdown();

        return 0;
    }
    catch (const std::exception& e)
    {
        dns_filter::Logger::error(std::string("程序异常退出: ") + e.what());
        dns_filter::Logger::shutdown();
        return 1;
    }
}
