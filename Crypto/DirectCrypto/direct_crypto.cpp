#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstring>

#include "../ReferenceImplementations/ciphersuite/Kuznyechik.h"
#include "../ReferenceImplementations/hashfunc/Streebog.h"
#include "../ReferenceImplementations/hmac/HMAC512.h"
#include "../ReferenceImplementations/kdf/kdf.h"

// Вспомогательная функция для конвертации hex-строки в вектор байт
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Вспомогательная функция для конвертации вектора байт в hex-строку
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

void print_usage() {
    std::cout << "Использование программы:\n"
              << "direct_crypto <команда> [параметры]\n\n"
              << "Доступные команды:\n"
              << "  encrypt <алгоритм> <ключ> <данные>    - Шифрование данных\n"
              << "  decrypt <алгоритм> <ключ> <данные>    - Расшифрование данных\n"
              << "  hash <алгоритм> <данные>              - Вычисление хэша\n"
              << "  hmac <ключ> <данные>                  - Вычисление HMAC\n"
              << "  kdf <алгоритм> <соль> <длина>        - Генерация ключа\n\n"
              << "Параметры должны быть в шестнадцатеричном формате\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string command = argv[1];

    try {
        if (command == "encrypt") {
            if (argc != 5) {
                std::cout << "Ошибка: неверное количество параметров для шифрования\n";
                print_usage();
                return 1;
            }
            std::string algorithm = argv[2];
            std::vector<uint8_t> key = hex_to_bytes(argv[3]);
            std::vector<uint8_t> data = hex_to_bytes(argv[4]);
            
            // Здесь будет вызов соответствующей функции шифрования
            std::vector<uint8_t> encrypted; // = encrypt_data(algorithm, key, data);
            std::cout << "Зашифрованные данные: " << bytes_to_hex(encrypted) << std::endl;
        }
        else if (command == "decrypt") {
            if (argc != 5) {
                std::cout << "Ошибка: неверное количество параметров для расшифрования\n";
                print_usage();
                return 1;
            }
            std::string algorithm = argv[2];
            std::vector<uint8_t> key = hex_to_bytes(argv[3]);
            std::vector<uint8_t> data = hex_to_bytes(argv[4]);
            
            // Здесь будет вызов соответствующей функции расшифрования
            std::vector<uint8_t> decrypted; // = decrypt_data(algorithm, key, data);
            std::cout << "Расшифрованные данные: " << bytes_to_hex(decrypted) << std::endl;
        }
        else if (command == "hash") {
            if (argc != 4) {
                std::cout << "Ошибка: неверное количество параметров для хэширования\n";
                print_usage();
                return 1;
            }
            std::string algorithm = argv[2];
            std::vector<uint8_t> data = hex_to_bytes(argv[3]);
            
            // Здесь будет вызов соответствующей функции хэширования
            std::vector<uint8_t> hash; // = hash_data(algorithm, data);
            std::cout << "Хэш: " << bytes_to_hex(hash) << std::endl;
        }
        else if (command == "hmac") {
            if (argc != 4) {
                std::cout << "Ошибка: неверное количество параметров для HMAC\n";
                print_usage();
                return 1;
            }
            std::vector<uint8_t> key = hex_to_bytes(argv[2]);
            std::vector<uint8_t> data = hex_to_bytes(argv[3]);
            
            // Здесь будет вызов функции HMAC
            std::vector<uint8_t> hmac; // = calculate_hmac(key, data);
            std::cout << "HMAC: " << bytes_to_hex(hmac) << std::endl;
        }
        else if (command == "kdf") {
            if (argc != 5) {
                std::cout << "Ошибка: неверное количество параметров для KDF\n";
                print_usage();
                return 1;
            }
            std::string algorithm = argv[2];
            std::vector<uint8_t> salt = hex_to_bytes(argv[3]);
            int length = std::stoi(argv[4]);
            
            // Здесь будет вызов функции KDF
            std::vector<uint8_t> derived_key; // = derive_key(algorithm, salt, length);
            std::cout << "Сгенерированный ключ: " << bytes_to_hex(derived_key) << std::endl;
        }
        else {
            std::cout << "Неизвестная команда: " << command << std::endl;
            print_usage();
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 