#include "logger.h"
#include <filesystem>
#include <optional>

namespace dns_filter
{

    // 静态成员初始化
    std::shared_ptr<Logger> Logger::subscriber_ = nullptr;
    std::shared_ptr<spdlog::logger> Logger::logger_ = nullptr;

    void Logger::init()
    {
        Configer& configer = Configer::get_configer();
        if (!subscriber_)
        {
            subscriber_ = std::make_shared<Logger>();
            configer.subscribe("logging", subscriber_);
        }

        rebuild_from_config();
    }

    void Logger::update(const std::string &key)
    {
        if (key == "logging")
        {
            // logging 下任意字段变更，重新构建日志器
            rebuild_from_config();
        }
    }

    void Logger::rebuild_from_config()
    {
        Configer &configer = Configer::get_configer();
        const auto log_file = configer.logging_file().value_or("logs/dns_filter.log");
        const auto log_level = configer.logging_level().value_or("info");
        const auto log_max_size = configer.logging_max_size_mb().value_or(10);
        const auto log_max_files = configer.logging_max_files().value_or(5);

        try
        {
            // 创建日志目录
            std::filesystem::path log_path(log_file);
            if (log_path.has_parent_path())
            {
                std::filesystem::create_directories(log_path.parent_path());
            }

            // 创建文件输出sink（支持轮转）
            //一个sink对应一个输出目标，这里我们创建了一个文件sink和一个控制台sink，分别负责将日志输出到文件和控制台。
            //支持轮转意思是当日志文件达到指定大小时，spdlog会自动将当前日志文件重命名为一个备份文件，并创建一个新的日志文件继续写入日志。这种机制可以防止单个日志文件过大，便于管理和查看日志。
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file,
                log_max_size * 1024 * 1024,
                log_max_files);

            // 创建控制台输出sink
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

            // 设置sink格式
            file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
            console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");

            // 创建多目标日志器
            std::vector<spdlog::sink_ptr> sinks{file_sink, console_sink};
            // 日志器是spdlog::logger负责管理日志的输出和格式化。通过创建一个多目标日志器，我们可以同时将日志输出到多个地方（例如文件和控制台）。
            if (spdlog::get("dns_filter"))
            {
                spdlog::drop("dns_filter");
            }
            logger_ = std::make_shared<spdlog::logger>("dns_filter", sinks.begin(), sinks.end());

            // 设置日志级别
            logger_->set_level(parse_level(log_level));

            // 设置立即刷新（遇到error级别立即刷盘）
            logger_->flush_on(spdlog::level::err);

            // 注册为默认日志器
            spdlog::register_logger(logger_);
            spdlog::set_default_logger(logger_);

            // 输出初始化信息
            logger_->info("Logger initialized: file={}, level={}, max_size={}MB, max_files={}",
                          log_file, log_level, log_max_size, log_max_files);
        }
        catch (const std::exception &e)
        {
            fprintf(stderr, "Logger initialization failed: %s\n", e.what());
        }
    }

    void Logger::shutdown()
    {
        Configer &configer = Configer::get_configer();
        if (subscriber_)
        {
            configer.unsubscribe("logging", subscriber_);
            subscriber_.reset();
        }

        if (logger_)
        {
            logger_->info("Logger shutting down");
            spdlog::shutdown();
            logger_ = nullptr;
        }
    }

    void Logger::debug(const std::string &msg)
    {
        if (logger_)
        {
            logger_->debug(msg);
        }
    }

    void Logger::info(const std::string &msg)
    {
        if (logger_)
        {
            logger_->info(msg);
        }
    }

    void Logger::warn(const std::string &msg)
    {
        if (logger_)
        {
            logger_->warn(msg);
        }
    }

    void Logger::error(const std::string &msg)
    {
        if (logger_)
        {
            logger_->error(msg);
        }
    }

    spdlog::level::level_enum Logger::parse_level(const std::string &level)
    {
        if (level == "debug" || level == "DEBUG")
        {
            return spdlog::level::debug;
        }
        else if (level == "info" || level == "INFO")
        {
            return spdlog::level::info;
        }
        else if (level == "warn" || level == "WARN" || level == "warning")
        {
            return spdlog::level::warn;
        }
        else if (level == "error" || level == "ERROR")
        {
            return spdlog::level::err;
        }
        else
        {
            return spdlog::level::info; // 默认info级别
        }
    }

} // namespace dns_filter
