#include "Steganography.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;

namespace
{
bool readBinaryFile(const string &filename, vector<char> &data)
{
    ifstream in(filename, ios::binary);
    if (!in)
    {
        cout << "Failed to open file '" << filename << "'.\n";
        return false;
    }

    in.seekg(0, ios::end);
    streamoff size = in.tellg();
    if (size < 0)
    {
        cout << "Failed to read file '" << filename << "'.\n";
        return false;
    }
    in.seekg(0, ios::beg);

    data.assign(static_cast<size_t>(size), 0);
    if (!data.empty())
    {
        in.read(&data[0], data.size());
        if (!in)
        {
            cout << "Failed to read file '" << filename << "'.\n";
            return false;
        }
    }

    return true;
}

bool writeBinaryFile(const string &filename, const vector<char> &data)
{
    ofstream out(filename, ios::binary);
    if (!out)
    {
        cout << "Failed to write file '" << filename << "'.\n";
        return false;
    }

    if (!data.empty())
    {
        out.write(&data[0], data.size());
        if (!out)
        {
            cout << "Failed to write file '" << filename << "'.\n";
            return false;
        }
    }

    return true;
}

uint32_t readLittleEndian32(const vector<char> &data, size_t offset)
{
    return static_cast<uint32_t>(static_cast<unsigned char>(data[offset])) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 1])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 2])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 3])) << 24);
}

void appendLittleEndian32(vector<char> &data, uint32_t value)
{
    data.push_back(static_cast<char>(value & 0xFF));
    data.push_back(static_cast<char>((value >> 8) & 0xFF));
    data.push_back(static_cast<char>((value >> 16) & 0xFF));
    data.push_back(static_cast<char>((value >> 24) & 0xFF));
}

string getBaseName(const string &path)
{
    size_t slashPos = path.find_last_of("/\\");
    if (slashPos == string::npos)
        return path;
    return path.substr(slashPos + 1);
}

bool readEmbeddedByte(const vector<char> &carrierData, int startIndex, char &value)
{
    if (startIndex < 0 || startIndex + 7 >= static_cast<int>(carrierData.size()))
        return false;

    unsigned char result = 0;
    for (int bit = 0; bit < 8; ++bit)
    {
        unsigned char carrierByte = static_cast<unsigned char>(carrierData[startIndex + bit]);
        result = static_cast<unsigned char>((result << 1) | (carrierByte & 1));
    }

    value = static_cast<char>(result);
    return true;
}

bool readEmbeddedBytes(const vector<char> &carrierData, int startIndex, int byteCount, vector<char> &output)
{
    output.clear();
    if (byteCount < 0)
        return false;

    int requiredBits = byteCount * 8;
    if (startIndex < 0 || startIndex + requiredBits > static_cast<int>(carrierData.size()))
        return false;

    output.reserve(byteCount);
    for (int i = 0; i < byteCount; ++i)
    {
        char value = 0;
        if (!readEmbeddedByte(carrierData, startIndex + (i * 8), value))
            return false;
        output.push_back(value);
    }

    return true;
}
} // namespace

namespace Steganography
{
string hideMessage(const string &text, const string &secret)
{
    return text + "<hidden>" + secret;
}

string extractMessage(const string &text)
{
    size_t pos = text.find("<hidden>");
    if (pos == string::npos)
        return "";
    return text.substr(pos + 8);
}

bool hideFileInBmp(const string &secretFilename, const string &carrierFilename, const string &outputFilename)
{
    vector<char> carrierData;
    vector<char> secretData;
    vector<char> payload;

    if (!readBinaryFile(carrierFilename, carrierData))
        return false;
    if (!readBinaryFile(secretFilename, secretData))
        return false;

    if (carrierData.size() < 54)
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    if (carrierData[0] != 'B' || carrierData[1] != 'M')
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    int pixelDataOffset = static_cast<int>(readLittleEndian32(carrierData, 10));
    if (pixelDataOffset < 0 || pixelDataOffset >= static_cast<int>(carrierData.size()))
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    string baseName = getBaseName(secretFilename);
    payload.push_back('E');
    payload.push_back('C');
    payload.push_back('S');
    payload.push_back('1');
    appendLittleEndian32(payload, static_cast<uint32_t>(baseName.size()));
    appendLittleEndian32(payload, static_cast<uint32_t>(secretData.size()));
    payload.insert(payload.end(), baseName.begin(), baseName.end());
    payload.insert(payload.end(), secretData.begin(), secretData.end());

    int pixelBytes = static_cast<int>(carrierData.size()) - pixelDataOffset;
    int requiredBits = static_cast<int>(payload.size()) * 8;
    if (pixelBytes < requiredBits)
    {
        cout << "Carrier image too small.\n";
        return false;
    }

    int carrierIndex = pixelDataOffset;
    for (size_t i = 0; i < payload.size(); ++i)
    {
        unsigned char currentByte = static_cast<unsigned char>(payload[i]);
        for (int bit = 7; bit >= 0; --bit)
        {
            int payloadBit = (currentByte >> bit) & 1;
            unsigned char carrierByte = static_cast<unsigned char>(carrierData[carrierIndex]);
            carrierByte = static_cast<unsigned char>((carrierByte & 0xFE) | payloadBit);
            carrierData[carrierIndex] = static_cast<char>(carrierByte);
            carrierIndex++;
        }
    }

    if (!writeBinaryFile(outputFilename, carrierData))
        return false;

    cout << "Embedded file saved as '" << outputFilename << "'.\n";
    return true;
}

bool extractFileFromBmp(const string &bmpFilename)
{
    vector<char> carrierData;
    vector<char> headerData;
    vector<char> filenameData;
    vector<char> payloadData;

    if (!readBinaryFile(bmpFilename, carrierData))
        return false;

    if (carrierData.size() < 54)
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    if (carrierData[0] != 'B' || carrierData[1] != 'M')
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    int pixelDataOffset = static_cast<int>(readLittleEndian32(carrierData, 10));
    if (pixelDataOffset < 0 || pixelDataOffset >= static_cast<int>(carrierData.size()))
    {
        cout << "Invalid BMP file.\n";
        return false;
    }

    if (!readEmbeddedBytes(carrierData, pixelDataOffset, 12, headerData))
    {
        cout << "No embedded file found.\n";
        return false;
    }

    if (headerData[0] != 'E' || headerData[1] != 'C' || headerData[2] != 'S' || headerData[3] != '1')
    {
        cout << "No embedded file found.\n";
        return false;
    }

    int filenameLength = static_cast<int>(readLittleEndian32(headerData, 4));
    int payloadLength = static_cast<int>(readLittleEndian32(headerData, 8));
    if (filenameLength <= 0 || payloadLength < 0)
    {
        cout << "Embedded file is corrupted.\n";
        return false;
    }

    int totalBytes = 12 + filenameLength + payloadLength;
    int pixelBytes = static_cast<int>(carrierData.size()) - pixelDataOffset;
    if (pixelBytes < totalBytes * 8)
    {
        cout << "Embedded file is corrupted.\n";
        return false;
    }

    if (!readEmbeddedBytes(carrierData, pixelDataOffset + (12 * 8), filenameLength, filenameData))
    {
        cout << "Embedded file is corrupted.\n";
        return false;
    }

    string outputFilename(filenameData.begin(), filenameData.end());
    if (outputFilename.empty())
    {
        cout << "Embedded file is corrupted.\n";
        return false;
    }

    if (!readEmbeddedBytes(carrierData, pixelDataOffset + ((12 + filenameLength) * 8), payloadLength, payloadData))
    {
        cout << "Embedded file is corrupted.\n";
        return false;
    }

    if (!writeBinaryFile(outputFilename, payloadData))
        return false;

    cout << "Extracted file saved as '" << outputFilename << "'.\n";
    return true;
}
} // namespace Steganography
