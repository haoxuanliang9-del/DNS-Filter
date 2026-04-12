#pragma once

#include <string>
#include <memory>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "config.h"
#include "configsubscriber.h"

namespace dns_filter {

class Logger: public ConfigSubscriber
{
public:
    // 初始化日志系统
    static void init();
    
    // 关闭日志系统
    static void shutdown();
    
    // 基础日志接口
    static void debug(const std::string& msg);
    static void info(const std::string& msg);
    static void warn(const std::string& msg);
    static void error(const std::string& msg);

    void update(const std::string &key) override;
    
    // 格式化日志接口（支持参数）
    template<typename... Args>
    static void debug(const char* fmt, Args&&... args) {
        if (logger_) {
            logger_->debug(fmt, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    static void info(const char* fmt, Args&&... args) {
        if (logger_) {
            logger_->info(fmt, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    static void warn(const char* fmt, Args&&... args) {
        if (logger_) {
            logger_->warn(fmt, std::forward<Args>(args)...);
        }
    }
    
    template<typename... Args>
    static void error(const char* fmt, Args&&... args) {
        if (logger_) {
            logger_->error(fmt, std::forward<Args>(args)...);
        }
    }

    

private:
    static void rebuild_from_config();

    // 订阅配置热更新的代理实例
    static std::shared_ptr<Logger> subscriber_;

    // spdlog日志器实例
    static std::shared_ptr<spdlog::logger> logger_;
    
    // 日志级别转换
    // 忽略level以下级别的日志输出
    static spdlog::level::level_enum parse_level(const std::string& level);
};

} // namespace dns_filter
