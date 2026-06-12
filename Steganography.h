#pragma once

#include <string>

namespace Steganography
{
std::string hideMessage(const std::string &text, const std::string &secret);
std::string extractMessage(const std::string &text);
bool hideFileInBmp(const std::string &secretFilename, const std::string &carrierFilename, const std::string &outputFilename);
bool extractFileFromBmp(const std::string &bmpFilename);
}
