#include "ConfigStore.h"

#include <fstream>

namespace
{
inline std::string trim(const std::string &value)
{
    const char *whitespace = " \t\n\r";
    const auto begin = value.find_first_not_of(whitespace);
    if (begin == std::string::npos)
        return std::string();
    const auto end = value.find_last_not_of(whitespace);
    return value.substr(begin, end - begin + 1);
}

bool parseLine(const std::string &line, std::string &key, std::string &value)
{
    const auto pos = line.find('=');
    if (pos == std::string::npos)
        return false;

    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}
} // namespace

bool ConfigStore::save(const CipherConfig &cfg, const std::string &filename)
{
    std::ofstream out(filename);
    if (!out)
        return false;

    out << "type=" << cfg.type << '\n';
    for (const auto &entry : cfg.params)
    {
        out << entry.first << "=" << entry.second << '\n';
    }

    return static_cast<bool>(out);
}

std::optional<CipherConfig> ConfigStore::load(const std::string &filename)
{
    std::ifstream in(filename);
    if (!in)
        return std::nullopt;

    CipherConfig cfg;
    std::string line;
    std::unordered_map<std::string, std::string> params;

    while (std::getline(in, line))
    {
        line = trim(line);
        if (line.empty() || line[0] == '#')
            continue;

        std::string key;
        std::string value;
        if (!parseLine(line, key, value))
            continue;

        if (key == "type")
            cfg.type = value;
        else
            params.emplace(key, value);
    }

    if (cfg.type.empty())
        return std::nullopt;

    cfg.params = std::move(params);
    return cfg;
}
