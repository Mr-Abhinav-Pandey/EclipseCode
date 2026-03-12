#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <memory>
#include <algorithm>
#include <unordered_set>
#include <thread>
#include <chrono>
#include <iomanip>
#include <unordered_map>

using namespace std;

class Cipher
{
public:
    virtual string encrypt(const string &text) = 0;
    virtual string decrypt(const string &text) = 0;
    virtual ~Cipher() {}
};

class CaesarCipher : public Cipher
{
    int shift;
public:
    explicit CaesarCipher(int s) : shift(s % 26) {}

    string encrypt(const string &text) override
    {
        string result;
        for (char c : text)
        {
            if (isalpha(static_cast<unsigned char>(c)))
            {
                char base = isupper(static_cast<unsigned char>(c)) ? 'A' : 'a';
                result += static_cast<char>((c - base + shift + 26) % 26 + base);
            }
            else
            {
                result += c;
            }
        }
        return result;
    }

    string decrypt(const string &text) override
    {
        string result;
        for (char c : text)
        {
            if (isalpha(static_cast<unsigned char>(c)))
            {
                char base = isupper(static_cast<unsigned char>(c)) ? 'A' : 'a';
                result += static_cast<char>((c - base - shift + 26) % 26 + base);
            }
            else
            {
                result += c;
            }
        }
        return result;
    }
};

class XORCipher : public Cipher
{
    string key;

    string toHex(const string &input)
    {
        stringstream ss;
        ss << hex << setfill('0');
        for (unsigned char c : input)
            ss << setw(2) << static_cast<int>(c);
        return ss.str();
    }

    string fromHex(const string &input)
    {
        string output;
        if (input.length() % 2 != 0)
        {
            return "";
        }
        for (size_t i = 0; i < input.length(); i += 2)
        {
            string byte = input.substr(i, 2);
            char c = static_cast<char>(strtol(byte.c_str(), nullptr, 16));
            output += c;
        }
        return output;
    }

public:
    explicit XORCipher(string k = "key") : key(move(k)) {}

    string encrypt(const string &text) override
    {
        string result = text;
        for (size_t i = 0; i < result.size(); i++)
            result[i] ^= key[i % key.size()];
        return toHex(result);
    }

    string decrypt(const string &text) override
    {
        string decoded = fromHex(text);
        if (decoded.empty())
            return "";

        for (size_t i = 0; i < decoded.size(); ++i)
            decoded[i] ^= key[i % key.size()];
        return decoded;
    }
};

class VigenereCipher : public Cipher
{
    string key;
public:
    explicit VigenereCipher(string k = "KEY") : key(move(k))
    {
        transform(key.begin(), key.end(), key.begin(), ::toupper);
    }

    string encrypt(const string &text) override
    {
        string result;
        size_t keyIndex = 0;
        for (char c : text)
        {
            if (isalpha(static_cast<unsigned char>(c)))
            {
                char base = isupper(static_cast<unsigned char>(c)) ? 'A' : 'a';
                int shift = key[keyIndex % key.size()] - 'A';
                char encryptedChar = (c - base + shift) % 26 + base;
                result.push_back(encryptedChar);
                keyIndex++;
            }
            else
            {
                result.push_back(c);
            }
        }
        return result;
    }

    string decrypt(const string &text) override
    {
        string result;
        size_t keyIndex = 0;
        for (char c : text)
        {
            if (isalpha(static_cast<unsigned char>(c)))
            {
                char base = isupper(static_cast<unsigned char>(c)) ? 'A' : 'a';
                int shift = key[keyIndex % key.size()] - 'A';
                char decryptedChar = (c - base - shift + 26) % 26 + base;
                result.push_back(decryptedChar);
                keyIndex++;
            }
            else
            {
                result.push_back(c);
            }
        }
        return result;
    }
};

class SubstitutionCipher : public Cipher
{
    string key;
    string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unordered_map<char, char> encMap;
    unordered_map<char, char> decMap;

    void generateMaps()
    {
        for (size_t i = 0; i < 26; ++i)
        {
            encMap[alphabet[i]] = key[i];
            decMap[key[i]] = alphabet[i];
        }
    }

public:
    explicit SubstitutionCipher(const string &k) : key(k)
    {
        if (key.size() != 26)
            throw invalid_argument("Substitution key must be exactly 26 characters");

        unordered_set<char> seen;
        for (size_t i = 0; i < 26; ++i)
        {
            char c = toupper(static_cast<unsigned char>(key[i]));
            if (!isalpha(c))
                throw invalid_argument("Key must contain only alphabetic characters");

            if (seen.count(c))
                throw invalid_argument("Key contains duplicate characters");

            seen.insert(c);
            key[i] = c;
        }
        generateMaps();
    }

    string encrypt(const string &text) override
    {
        string result;
        for (char c : text)
        {
            char up = toupper(static_cast<unsigned char>(c));
            if (isalpha(up))
            {
                char encChar = encMap[up];
                if (isupper(static_cast<unsigned char>(c)))
                    result.push_back(encChar);
                else
                    result.push_back(tolower(encChar));
            }
            else
            {
                result.push_back(c);
            }
        }
        return result;
    }

    string decrypt(const string &text) override
    {
        string result;
        for (char c : text)
        {
            char up = toupper(static_cast<unsigned char>(c));
            if (isalpha(up))
            {
                char decChar = decMap[up];
                if (isupper(static_cast<unsigned char>(c)))
                    result.push_back(decChar);
                else
                    result.push_back(tolower(decChar));
            }
            else
            {
                result.push_back(c);
            }
        }
        return result;
    }
};

class FileHandler
{
public:
    static void ensureFileExists(const string &filename)
    {
        ifstream in(filename);
        if (!in.good())
        {
            ofstream out(filename);
        }
    }

    static string readFromFile(const string &filename)
    {
        ensureFileExists(filename);
        ifstream in(filename);
        if (!in)
        {
            cerr << "[FileHandler] Failed to open file '" << filename << "' for reading.\n";
            return "";
        }
        stringstream buffer;
        buffer << in.rdbuf();
        return buffer.str();
    }

    static bool saveToFile(const string &filename, const string &content)
    {
        ofstream out(filename);
        if (!out)
        {
            cerr << "[FileHandler] Failed to open file '" << filename << "' for writing.\n";
            return false;
        }
        out << content;
        return true;
    }
};

class Steganography
{
public:
    static string hideMessage(const string &text, const string &secret)
    {
        return text + "<hidden>" + secret;
    }

    static string extractMessage(const string &text)
    {
        size_t pos = text.find("<hidden>");
        if (pos == string::npos)
            return "";
        return text.substr(pos + 8);
    }
};

class Logger
{
    static const char *logFile;
    static const char *adminPassword;

public:
    static void logAction(const string &action, const string &status, const string &cipherType = "N/A")
    {
        ofstream out(logFile, ios::app);
        if (!out)
        {
            cerr << "[Logger] Unable to open log file for writing.\n";
            return;
        }
        auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        out << buf
            << " | Action: " << action
            << " | Status: " << status
            << " | Cipher: " << cipherType << endl;
    }

    static string readLogs()
    {
        return FileHandler::readFromFile(logFile);
    }

    static bool authenticateAdmin()
    {
        cout << "\n*** Admin Login Required ***\n";
        cout << "Enter password: ";
        string input;
        getline(cin, input);

        if (input == adminPassword)
        {
            cout << "Access granted.\n";
            return true;
        }
        else
        {
            cout << "Access denied. Incorrect password.\n";
            return false;
        }
    }

    static void viewLogs()
    {
        if (!authenticateAdmin())
        {
            cout << "Unable to display logs.\n";
            return;
        }

        string logs = readLogs();
        cout << "\n--- SYSTEM LOGS ---\n";
        if (logs.empty())
        {
            cout << "<No logs available>\n";
        }
        else
        {
            cout << logs << endl;
        }
    }
};

const char *Logger::logFile = "logs.txt";
const char *Logger::adminPassword = "admin123";

class ConfigManager
{
    static string encryptionType;

public:
    static void setEncryptionType(const string &type)
    {
        encryptionType = type;
    }
    static string getEncryptionType()
    {
        return encryptionType;
    }
};

string ConfigManager::encryptionType = "Caesar";


inline string trim(const string &s)
{
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == string::npos)
        return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

inline bool iequals(const string &a, const string &b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

int getIntInput(const string &prompt, int minVal = INT32_MIN, int maxVal = INT32_MAX)
{
    int val;
    while (true)
    {
        cout << prompt;
        string input;
        getline(cin, input);
        stringstream ss(input);
        if (ss >> val && !(ss >> input))
        {
            if (val >= minVal && val <= maxVal)
                return val;
        }
        cout << "Invalid input. Please enter a number";
        if (minVal != INT32_MIN || maxVal != INT32_MAX)
            cout << " between " << minVal << " and " << maxVal;
        cout << ".\n";
    }
}

unique_ptr<Cipher> selectCipher()
{
    cout << "\nAvailable Ciphers:\n"
         << "1) Caesar Cipher\n"
         << "2) Vigenere Cipher\n"
         << "3) XOR Cipher\n"
         << "4) Substitution Cipher (user-defined key)\n"
         << "Enter choice (1-4): ";

    int choice = getIntInput("", 1, 4);

    switch (choice)
    {
    case 1:
    {
        int shift = getIntInput("Enter shift amount (integer between 1 and 25): ", 1, 25);
        ConfigManager::setEncryptionType("Caesar");
        return make_unique<CaesarCipher>(shift);
    }
    case 2:
    {
        string key;
        while (true)
        {
            cout << "Enter key (alphabetic characters only): ";
            getline(cin, key);
            key = trim(key);
            if (!key.empty() && all_of(key.begin(), key.end(), ::isalpha))
                break;
            cout << "Invalid key. Please enter letters only.\n";
        }
        ConfigManager::setEncryptionType("Vigenere");
        return make_unique<VigenereCipher>(key);
    }
    case 3:
    {
        string key;
        while (true)
        {
            cout << "Enter key (non-empty string): ";
            getline(cin, key);
            key = trim(key);
            if (!key.empty())
                break;
            cout << "Key cannot be empty.\n";
        }
        ConfigManager::setEncryptionType("XOR");
        return make_unique<XORCipher>(key);
    }
    case 4:
    {
        string key;
        while (true)
        {
            cout << "Enter 26-character substitution key (A-Z, no duplicates): ";
            getline(cin, key);
            key = trim(key);
            if (key.length() != 26)
            {
                cout << "Key must be exactly 26 characters.\n";
                continue;
            }
            bool valid = true;
            unordered_set<char> seen;
            for (char c : key)
            {
                if (!isalpha(c))
                {
                    valid = false;
                    break;
                }
                char up = toupper(static_cast<unsigned char>(c));
                if (seen.count(up))
                {
                    valid = false;
                    break;
                }
                seen.insert(up);
            }
            if (!valid)
            {
                cout << "Key must contain only unique alphabetic characters.\n";
                continue;
            }
            try
            {
                ConfigManager::setEncryptionType("Substitution");
                return make_unique<SubstitutionCipher>(key);
            }
            catch (const invalid_argument &e)
            {
                cout << "Error: " << e.what() << endl;
            }
        }
    }
    default:
        return nullptr;
    }
}

void showTrialMode()
{
    cout << "\n--- Trial Mode ---\n";
    cout << "Try encrypting and decrypting two short messages.\n";

    for (int i = 1; i <= 2; ++i)
    {
        cout << "\nTrial " << i << " - Enter a short message (max 100 chars): ";
        string message;
        getline(cin, message);

        if (message.length() > 100)
        {
            cout << "Message too long for trial. Please keep it under 100 characters.\n";
            --i;
            continue;
        }

        auto cipher = selectCipher();

        if (!cipher)
        {
            cout << "Cipher selection failed, please try again.\n";
            --i;
            continue;
        }

        string encrypted = cipher->encrypt(message);
        string decrypted = cipher->decrypt(encrypted);

        cout << "\nEncrypted message: " << encrypted << "\n";
        cout << "Decrypted message: " << decrypted << "\n";
    }
}


bool simulatePayment()
{
    cout << "\n--- Subscription Payment ---\n";

    string fullName, cardNum, expiry, cvv;

    while (true)
    {
        cout << "Enter Full Name: ";
        getline(cin, fullName);
        fullName = trim(fullName);
        if (!fullName.empty())
            break;
        cout << "Name cannot be empty.\n";
    }

    while (true)
    {
        cout << "Enter Card Number (16 digits): ";
        getline(cin, cardNum);
        if (cardNum.length() == 16 && all_of(cardNum.begin(), cardNum.end(), ::isdigit))
            break;
        cout << "Invalid card number. Must be exactly 16 digits.\n";
    }

    while (true)
    {
        cout << "Enter Expiry Date (MM/YY): ";
        getline(cin, expiry);
        if (expiry.length() == 5 && expiry[2] == '/' &&
            all_of(expiry.begin(), expiry.begin() + 2, ::isdigit) &&
            all_of(expiry.begin() + 3, expiry.end(), ::isdigit))
        {
            int month = stoi(expiry.substr(0, 2));
            if (month >= 1 && month <= 12)
                break;
        }
        cout << "Invalid expiry date format or month. Please use MM/YY.\n";
    }

    while (true)
    {
        cout << "Enter CVV (3 digits): ";
        getline(cin, cvv);
        if (cvv.length() == 3 && all_of(cvv.begin(), cvv.end(), ::isdigit))
            break;
        cout << "Invalid CVV. Must be exactly 3 digits.\n";
    }

    cout << "\nProcessing payment";
    for (int i = 0; i < 5; ++i)
    {
        cout << '.';
        cout.flush();
        this_thread::sleep_for(chrono::milliseconds(600));
    }
    cout << "\nPayment successful! Subscription activated.\n";

    Logger::logAction("Payment", "Success");

    return true;
}

void encryptionSystem()
{
    bool exitFlag = false;
    while (!exitFlag)
    {
        cout << "\n--- Encryption System Menu ---\n";
        cout << "1) Encrypt File (test.txt)\n";
        cout << "2) Decrypt File (test_enc.txt)\n";
        cout << "3) View Logs (Admin Only)\n";
        cout << "4) Exit\n";
        cout << "Select an option (1-4): ";

        int choice = getIntInput("", 1, 4);

        const string inputFile = "test.txt";
        const string encryptedFile = "test_enc.txt";
        const string decryptedFile = "test_dec.txt";

        if (choice == 4)
        {
            cout << "Exiting Encryption System. Goodbye.\n";
            exitFlag = true;
            continue;
        }
        else if (choice == 3)
        {
            Logger::viewLogs();
            continue;
        }

        auto cipher = selectCipher();
        if (!cipher)
        {
            cout << "Cipher initialization failed. Please try again.\n";
            continue;
        }

        if (choice == 1)
        {
            string msg = FileHandler::readFromFile(inputFile);
            if (msg.empty())
            {
                cout << "Failed to read from '" << inputFile << "'. Confirm the file exists and is not empty.\n";
                continue;
            }

            cout << "Encrypting file content...\n";
            string encryptedMsg = cipher->encrypt(msg);

            cout << "You can optionally enter a secret message to hide inside encrypted file (max 100 chars).\n";
            string secret;
            getline(cin, secret);
            if (secret.length() > 100)
            {
                cout << "Secret message too long, truncating to 100 characters.\n";
                secret = secret.substr(0, 100);
            }

            string combined = Steganography::hideMessage(encryptedMsg, secret);

            bool saved = FileHandler::saveToFile(encryptedFile, combined);
            if (saved)
            {
                cout << "Encrypted file saved as '" << encryptedFile << "'.\n";
                Logger::logAction("Encrypt", "Success", ConfigManager::getEncryptionType());
            }
            else
            {
                cout << "Failed to save encrypted file.\n";
                Logger::logAction("Encrypt", "Failed", ConfigManager::getEncryptionType());
            }
        }
        else if (choice == 2)
        {
            string encData = FileHandler::readFromFile(encryptedFile);
            if (encData.empty())
            {
                cout << "Failed to read from '" << encryptedFile << "'. Confirm the file exists and is not empty.\n";
                continue;
            }

            size_t pos = encData.find("<hidden>");
            string ciphertext, secret;
            if (pos != string::npos)
            {
                ciphertext = encData.substr(0, pos);
                secret = encData.substr(pos + 8);
            }
            else
            {
                ciphertext = encData;
                secret = "";
            }

            cout << "Decrypting...\n";
            string decrypted = cipher->decrypt(ciphertext);

            cout << "\nDecrypted Content:\n" << decrypted << "\n";
            if (!secret.empty())
            {
                cout << "Extracted hidden message: '" << secret << "'\n";
            }

            bool saved = FileHandler::saveToFile(decryptedFile, decrypted);
            if (saved)
            {
                cout << "Decrypted content saved to '" << decryptedFile << "'.\n";
                Logger::logAction("Decrypt", "Success", ConfigManager::getEncryptionType());
            }
            else
            {
                cout << "Failed to save decrypted file.\n";
                Logger::logAction("Decrypt", "Failed", ConfigManager::getEncryptionType());
            }
        }
    }
}

int main()
{
    cout << "Welcome to the Extended EclipseCode Encryption Tool\n";
    cout << "You may try our trial mode with short messages before subscribing.\n";
    cout << "Press Enter to continue with trial mode, or 's' then Enter to skip trial: ";
    string input;
    getline(cin, input);
    if (input.empty() || tolower(input[0]) != 's')
    {
        showTrialMode();
    }

    cout << "\nWould you like to subscribe for full features? (y/n): ";
    while (true)
    {
        getline(cin, input);
        if (input.empty()) continue;
        char ch = tolower(input[0]);
        if (ch == 'y')
        {
            if (!simulatePayment())
            {
                cout << "Payment failed. Exiting program.\n";
                return 1;
            }
            encryptionSystem();
            break;
        }
        else if (ch == 'n')
        {
            cout << "Thank you for trying EclipseCode Encryption Tool. Goodbye!\n";
            break;
        }
        else
            cout << "Invalid input. Please enter 'y' or 'n': ";
    }

    return 0;
}

