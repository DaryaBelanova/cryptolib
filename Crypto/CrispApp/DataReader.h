#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <cstdint>

class DataReader {

public:

	DataReader();

	void readFromFile(const std::string& filename);

	std::unordered_map<std::string, std::vector<uint8_t>> headerDataMap;

	std::unordered_map<std::string, std::vector<uint8_t>> payloadDataMap;

	std::unordered_map<std::string, std::vector<uint8_t>> crispDataMap;

	std::unordered_map<std::string, std::vector<uint8_t>> targetKeyDataMap;

private:

	std::vector<uint8_t> stringToBytes(const std::string& value);

	std::vector<uint8_t> decimalToBytes(uint64_t decimal);
};