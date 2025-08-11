//
// Created by the marooned on 8/10/2025.
//

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>

class config_parser {
private:
    std::map<std::string, std::string> config_values;
    std::string confi_file_path;

    //helper methods
    std::string trim(const std::string& str);
    bool is_comment_line(const std::string& line);
    bool pars_line(const std::string& line, std::string& key, std::string& value);

public:
    //constructure and destructor
    config_parser();
    config_parser(const std::string& file_path);
    ~config_parser();

    //file operations
    bool load_file_config(const std::string& file_path);
    bool save_file_config(const std::string& file_path = "");
    bool reload_file_config();

    //get value with type conversion
    std::string get_string(const std::string& key, const std::string& default_value = "");
    int get_int(const std::string& key, int default_value = 0);
    double get_double(const std::string& key, double default_value = 0.0);
    bool get_bool(const std::string& key, bool default_value = false);
    std::vector<std::string> get_string_list(const std::string& key, const std::vector<std::string>& default_value = {});

    //set value
    void set_string(const std::string& key, const std::string& value);
    void set_int(const std::string& key, int value);
    void set_bool(const std::string& key, bool value);
    void set_double(const std::string& key, double value);
    void set_string_list(const std::string& key, std::vector<std::string>& value);

    //utility methods
    void remove_key(const std::string& key);
    bool has_key(const std::string& key) const;
    void clear_all();
    void print_all() const;
    std::vector<std::string> get_all_keys() const;

    //validation methods
    bool validate_required_keys(std::vector<std::string>& required_keys) const;
    std::vector<std::string> get_missing_keys(std::vector<std::string>& required_keys) const;
};

#endif //CONFIG_PARSER_H
