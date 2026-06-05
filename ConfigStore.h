#pragma once

#include <optional>
#include <string>
#include <unordered_map>

struct CipherConfig
{
    std::string type;
    std::unordered_map<std::string, std::string> params;
};

class ConfigStore
{
public:
    static bool save(const CipherConfig &cfg, const std::string &filename = "eclipse.cfg");
    static std::optional<CipherConfig> load(const std::string &filename = "eclipse.cfg");
};
