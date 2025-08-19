//
// Created by the marooned on 8/16/2025.
//
#include "../../include/utils/logger.h"

#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace Utils {
    Logger &Logger::getInstance() {
        static Logger instance;
        return instance;
    }

    void Logger::log(LogLevel level,const std::string &message) {
        std::string time_stamp = getCurrentTimestamp();
        std::string level_str = levelToString(level);
        std::string log_message = '[' + time_stamp + ']' + '[' + level_str + ']' + message;

        if (console_output_) {
            if (level >= LogLevel::ERROR) {
                std::cerr << log_message << std::endl;
            } else {
                std::cout << log_message << std::endl;
            }
        }
        if (log_file_ && log_file_->is_open()) {
            *log_file_ << log_message << std::endl;
            log_file_->flush();
        }
    }

    void Logger::set_loglevel(LogLevel level) {
        current_level_ = level;
    }

    void Logger::set_logfile(const std::string &filename) {
        std::lock_guard<std::mutex> Lock(log_mutex_);
        log_file_ = std::make_unique<std::ofstream>(filename,std::ios::app);
        if (!log_file_->is_open()) {
            std::cerr << "Failed to open log file: " << filename <<std::endl;
        }
    }

    void Logger::enable_console_output(bool enable) {
        console_output_ = enable;
    }

    std::string Logger::levelToString(LogLevel level) const {
        switch (level) {
            case LogLevel::DEBUG : return "DEBUG";
            case LogLevel::INFO : return "INFO";
            case LogLevel::WARNING : return "WARNING";
            case LogLevel::ERROR : return "ERROR";
            case LogLevel::CRITICAL : return "CRITICAL";
            default: return "UNKNOWN";
        }
    }

    std::string Logger::getCurrentTimestamp() const {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch())%1000;
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

        return oss.str();
    }
}