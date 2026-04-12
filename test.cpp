#include "config.h"
#include "logger.h"

#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void require(bool condition, const std::string &message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void test_configer_singleton()
{
    auto &config1 = dns_filter::Configer::get_configer();
    auto &config2 = dns_filter::Configer::get_configer();
    require(&config1 == &config2, "Configer singleton failed");
}

void test_configer_init()
{
    auto &config = dns_filter::Configer::get_configer();
    config.config_init();

    auto addr = config.listen_addr();
    require(addr.has_value(), "listen_addr missing after init");

    auto port = config.listen_port();
    require(port.has_value(), "listen_port missing after init");
    require(*port > 0, "listen_port must be positive");
    require(*port <= 65535, "listen_port out of range");

    auto upstream = config.upstream_dns();
    require(upstream.has_value(), "upstream_dns missing after init");
    require(!upstream->empty(), "upstream_dns must not be empty");
}

void test_configer_reload()
{
    auto &config = dns_filter::Configer::get_configer();

    nlohmann::json new_config = {
        {"server", {{"listen_addr", "0.0.0.0"}, {"listen_port", 5353}}}
    };

    require(true, "precondition");
    config.config_reload(new_config);

    auto port = config.listen_port();
    require(port.has_value(), "listen_port missing after reload");
    require(*port == 5353, "listen_port not updated to 5353");

    auto addr = config.listen_addr();
    require(addr.has_value(), "listen_addr missing after reload");
    require(*addr == "0.0.0.0", "listen_addr not updated to 0.0.0.0");
}

void test_configer_subscriber()
{
    class TestSubscriber : public ConfigSubscriber
    {
    public:
        bool updated = false;

        void update(const std::string &key) override
        {
            if (key == "logging")
            {
                updated = true;
            }
        }
    };

    auto &config = dns_filter::Configer::get_configer();
    auto subscriber = std::make_shared<TestSubscriber>();

    config.subscribe("logging", subscriber);

    nlohmann::json new_config = {
        {"logging", {{"level", "debug"}}}
    };
    config.config_reload(new_config);

    require(subscriber->updated, "subscriber was not notified");

    config.unsubscribe("logging", subscriber);
}

void test_logger_init_and_output()
{
    struct LoggerGuard
    {
        ~LoggerGuard()
        {
            dns_filter::Logger::shutdown();
        }
    } guard;

    require(true, "logger guard ready");
    dns_filter::Logger::init();
    dns_filter::Logger::debug("test debug message");
    dns_filter::Logger::info("test info message");
    dns_filter::Logger::warn("test warn message");
    dns_filter::Logger::error("test error message");
    dns_filter::Logger::info("format test: {}", 42);
    dns_filter::Logger::info("multi args: {} {}", "str", 123);
}

void test_logger_config_update()
{
    dns_filter::Logger::init();
    auto &config = dns_filter::Configer::get_configer();

    nlohmann::json new_config = {
        {"logging", {{"level", "debug"}, {"file", "test.log"}, {"max_size_mb", 10}, {"max_files", 5}}}
    };

    config.config_reload(new_config);
    dns_filter::Logger::shutdown();
}

void test_configer_error_handling()
{
    auto &config = dns_filter::Configer::get_configer();

    nlohmann::json empty_config;
    config.config_reload(empty_config);

    nlohmann::json bad_port_config = {
        {"server", {{"listen_port", -1}}}
    };
    config.config_reload(bad_port_config);
}

struct TestCase
{
    const char *name;
    void (*fn)();
};

} // namespace

int main()
{
    const std::vector<TestCase> cases = {
        {"Configer - 单例模式测试", test_configer_singleton},
        {"Configer - 配置初始化", test_configer_init},
        {"Configer - 配置热更新", test_configer_reload},
        {"Configer - 订阅者模式", test_configer_subscriber},
        {"Logger - 初始化与日志输出", test_logger_init_and_output},
        {"Logger - 配置更新响应", test_logger_config_update},
        {"Configer - 错误配置处理", test_configer_error_handling},
    };

    int failed = 0;
    for (const auto &test_case : cases)
    {
        try
        {
            test_case.fn();
            std::cout << "[PASS] " << test_case.name << '\n';
        }
        catch (const std::exception &e)
        {
            ++failed;
            std::cerr << "[FAIL] " << test_case.name << ": " << e.what() << '\n';
        }
        catch (...)
        {
            ++failed;
            std::cerr << "[FAIL] " << test_case.name << ": unknown exception" << '\n';
        }
    }

    std::cout << "\nTotal: " << cases.size() << ", Failed: " << failed << '\n';
    return failed == 0 ? 0 : 1;
}
