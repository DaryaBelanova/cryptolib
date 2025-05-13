#ifndef REFERENCEIMPLEMENTATIONS_APPMSGPAYLOAD_H
#define REFERENCEIMPLEMENTATIONS_APPMSGPAYLOAD_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>



	class AppMsgPayload {

	public:

		virtual std::vector<uint8_t> get_bytes() = 0;

		virtual std::string to_string() = 0;

		std::string vector_to_hex_str(const std::vector<uint8_t>& vec) {
			std::stringstream ss;
			int count = 0;
			for (unsigned char i : vec) {
				ss << std::hex << std::setfill('0') << std::setw(2) << (int)i;
				++count;
			}
			return ss.str();
		}
	};


#endif //REFERENCEIMPLEMENTATIONS_APPMSGPAYLOAD_H