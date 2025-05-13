#include <cerrno>
#include <cstring>
#include "DataReader.h"

DataReader::DataReader() : headerDataMap(), payloadDataMap() {

}

void DataReader::readFromFile(const std::string& filename) {
	std::ifstream file(filename);
	if (!file.is_open()) {
		std::cerr << "Can't open file: " << filename << " Error: " << std::strerror(errno) << std::endl;
		return;
	}

	std::string line;
	enum class Section {
		None, Header, Payload, Crisp, TargetKey
	};
	Section currSection = Section::None;
	while (std::getline(file, line)) {
		if (line.find("----") == 0) {
			continue;
		}
		if (line.find("---M") == 0) {
			if (line == "---Message header---") {
				currSection = Section::Header;
			}
			if (line == "---Message body params---") {
				currSection = Section::Payload;
			}
			if (line == "---Message header---") {
				currSection = Section::Header;
			}
			continue;
		}
		if (line.find("---C") == 0) {
			currSection = Section::Crisp;
		}
		if (line.find("---R") == 0) {
			currSection = Section::TargetKey;
		}

		size_t colonPos = line.find(":");
		if (colonPos != std::string::npos) {
			std::string name = line.substr(0, colonPos);
			std::string values = line.substr(colonPos + 1);

			name.erase(0, name.find_first_not_of("\t"));
			//values.erase(0, values.find_last_not_of("\t"));

			std::istringstream iss(values);
			std::string value;
			while (iss >> value) {
				auto bytes = stringToBytes(value);
				switch (currSection) {
				case Section::Header:
					headerDataMap[name].insert(headerDataMap[name].end(), bytes.begin(), bytes.end());
					break;
				case Section::Payload:
					payloadDataMap[name].insert(payloadDataMap[name].end(), bytes.begin(), bytes.end());
					break;
				case Section::Crisp: 
					crispDataMap[name].insert(crispDataMap[name].end(), bytes.begin(), bytes.end());
					break;
				case Section::TargetKey:
					targetKeyDataMap[name].insert(targetKeyDataMap[name].end(), bytes.begin(), bytes.end());
					break;
				}

			}
		}
	}
	file.close();
}

std::vector<uint8_t> DataReader::decimalToBytes(uint64_t decimal) {
	std::vector<uint8_t> bytes;
	if (decimal == 0) {
		bytes.push_back(0);
		return bytes;
	}
	while (decimal > 0) {
		//bytes.push_back(static_cast<uint8_t>(decimal & 0xFF));
		bytes.insert(bytes.begin(), static_cast<uint8_t>(decimal & 0xFF));
		decimal >>= 8;
	}
	return bytes;
}

std::vector<uint8_t> DataReader::stringToBytes(const std::string& value) {
	std::vector<uint8_t> bytes;
	if (value.substr(0, 2) == "0x") {
		uint8_t byte = static_cast<uint8_t>(std::stoi(value.substr(2), nullptr, 16));
		bytes.push_back(byte);
	}
	else {
		uint64_t decimal = std::stoll(value);
		bytes = decimalToBytes(decimal);
	}

	return bytes;
}