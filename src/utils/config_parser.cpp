//
// Created by the marooned on 7/20/2025.
//
#include "config_parser.h"
#include <cctype> //::tolower
#include <algorithm> //std::transform


config_parser::config_parser() : confi_file_path(""){
}
config_parser::config_parser(const std::string& file_path) : confi_file_path(file_path) {
    load_file_config(file_path);
}
config_parser::~config_parser() {

}

std::string config_parser::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n ");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\r\n ");
    return str.substr(start,end-start+1);
}
bool config_parser::is_comment_line(const std::string& line) {
    std::string trimed_line = trim(line);
    return trimed_line.empty() || trimed_line[0] == '#' ||trimed_line[0] == ';';
}
bool config_parser::pars_line(const std::string& line, std::string &key, std::string& value) {
    size_t equal_pos = line.find('=');
    if (equal_pos  == std::string::npos) {
        return false;
    }
    key = trim(line.substr(0, equal_pos));
    value = trim(line.substr(equal_pos+1));

    //remove quotes
    if (value.length() >= 2 && ((value.front()=='"' && value.back()=='"')||(value.back()=='\'' && value.front() == '\''))) {
        value = value.substr(1,value.length()-2);
    }

    return !key.empty();
}


bool config_parser::load_file_config(const std::string& file_path) {
    confi_file_path = file_path;
    config_values.clear();

    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr<<"error while opening file check your path :"<<file_path<<std::endl;
        return false;
    }

    std::string line;
    int line_number = 0;
    while(std::getline(file,line)) {
        line_number++;
        if (is_comment_line(line)) {
            continue;
        }
        std::string key,value;
        if (pars_line(line, key, value)) {
            config_values[key] = value;
            std::cout<<"config applied: "<< key <<" = "<< value<<std::endl;
        }else {
            std::cerr<<"warning: invalid config line==>"<<line_number << ':' << line <<std::endl;
        }
    }
    file.close();
    std::cout<<"successfully applied "<<config_values.size()<<" config options"<<std::endl;
    return true;
}

bool config_parser::save_file_config(const std::string& file_path) {
    std::string output_path = file_path.empty() ? confi_file_path : file_path;

    if (output_path.empty()) {
        std::cerr<<"no file path"<<std::endl;
        return false;
    }

    std::fstream file(output_path);
    if (!file.is_open()) {
        std::cerr<<"can't open file check your path : "<<output_path<<std::endl;
        return false;
    }
    //write headers
    file << "# VPN Configuration File" << std::endl;
    file << "# Generated automatically - modify with care" << std::endl;
    file << std::endl;

    for (const auto& pair:config_values) {
        file<<pair.first<<" = "<<pair.second<<std::endl;
    }

    file.close();
    std::cout<<"Configurations are saved at :"<<output_path<<std::endl;
    return true;
}
bool config_parser::reload_file_config() {
    if (confi_file_path.empty()) {
        std::cerr << "error: no config file for reload"<<std::endl;
        return false;
    }
    return load_file_config(confi_file_path);
}

std::string config_parser::get_string(const std::string &key, const std::string &default_value) {
    auto item = config_values.find(key);
    if (item != config_values.end()) {
        return item->second;
    }
    return default_value;
}
int config_parser::get_int(const std::string &key, int default_value) {
    auto item = config_values.find(key);

    if (item != config_values.end()) {
        try {
            return std::stoi(item->second);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not convert '" << item->second
                      << "' to integer for key '" << key << "'" << std::endl;
        }
    }
    return default_value;
}
double config_parser::get_double(const std::string &key, double default_value) {
    auto item = config_values.find(key);
    if (item!= config_values.end()) {
        try {
            return std::stod(item->second);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not convert '" << item->second
                      << "' to double for key '" << key << "'" << std::endl;
        }
    }
    return default_value;
}
bool config_parser::get_bool(const std::string &key, bool default_value) {
    auto item = config_values.find(key);
    if (item != config_values.end()) {
        std::string value = item->second;
        std::transform(value.begin(), value.end(),value.begin(),::tolower);
        if (value == "true" || value == "1" || value == "yes" || value == "on"){
        return true;
        }else if (value == "false" || value == "0" || value == "no" || value == "off") {
            return false;
        }else {
            std::cerr << "Warning: Could not convert '" << item->second
                      << "' to boolean for key '" << key << "'" << std::endl;
        }
    }
    return default_value;
}

std::vector<std::string> config_parser::get_string_list(const std::string &key, const std::vector<std::string> &default_value) {
    auto item = config_values.find(key);
    if (item != config_values.end()) {
        std::vector<std::string> result;
        std::stringstream ss(item->second);
        std::string item1;
        while (std::getline(ss,item1,',')) {
            result.push_back(trim(item1));
        }
        return result;
    }
    return default_value;
}

void config_parser::set_string(const std::string &key, const std::string &value) {
     config_values[key] = value;
 }
void config_parser::set_int(const std::string &key, int value) {
    config_values[key] = std::to_string(value);
}
void config_parser::set_bool(const std::string &key, bool value) {
    config_values[key] = value ? "true" : "false";
}
void config_parser::set_double(const std::string &key, double value) {
    config_values[key] = std::to_string(value);
}
void config_parser::set_string_list(const std::string &key, std::vector<std::string> &value) {
    std::stringstream ss;
    for (size_t i = 0; i<value.size();i++ ) {
        if (i>0) {
            ss << ", ";
        }
        ss<< value[i];
    }
    config_values[key] = ss.str();
}

void config_parser::remove_key(const std::string &key) {
    config_values.erase(key);
}
bool config_parser::has_key(const std::string &key) const {
    return config_values.find(key) != config_values.end();
}
void config_parser::clear_all() {
    config_values.clear();
}
void config_parser::print_all() const {
    std::cout << "=== Configuration Values ===" << std::endl;
    for (const auto& pair : config_values) {
        std::cout<< pair.first <<" = "<<pair.second<<std::endl;
    }
    std::cout << "===========================" << std::endl;
}
std::vector<std::string> config_parser::get_all_keys() const {
    std::vector<std::string> result;
    for (const auto& pair:config_values) {
        result.push_back(pair.first);
    }
    return result;
}

bool config_parser::validate_required_keys(std::vector<std::string> &required_keys) const {
    for (const std::string& key : required_keys) {
        if (!has_key(key)) {
            return false;
        }
    }
    return true;
}
std::vector<std::string> config_parser::get_missing_keys(std::vector<std::string> &required_keys) const {
    std::vector<std::string> missing;
    for (const std::string& key : required_keys) {
        if (!has_key(key)) {
            missing.push_back(key);
        }
    }
    return missing;
}












