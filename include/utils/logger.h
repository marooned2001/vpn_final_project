//
// Created by the marooned on 8/16/2025.
//
#pragma once

#include <string>
#include <mutex>
#include <memory>
#include <fstream>

namespace Utils {
    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3,
        CRITICAL = 4
    };

    class Logger {
    private:
        Logger() = default;
        ~Logger() = default;
        Logger(const Logger&) = delete;
        Logger& operator = (const Logger&) = delete;

        LogLevel current_level_ = LogLevel::INFO;
        std::unique_ptr<std::ofstream> log_file_;
        bool console_output_ = true;
        std::mutex log_mutex_;

        std::string levelToString(LogLevel level) const;
        std::string getCurrentTimestamp() const;

    public:
        static Logger& getInstance();

        void log(LogLevel level,const std::string& message);
        void set_loglevel(LogLevel level);
        void set_logfile(const std::string& filename);
        void enable_console_output(bool enable);
    };
}