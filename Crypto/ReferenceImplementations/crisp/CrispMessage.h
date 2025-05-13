#ifndef REFERENCEIMPLEMENTATIONS_CRISPMESSAGE_H
#define REFERENCEIMPLEMENTATIONS_CRISPMESSAGE_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace Crisp {

	class CrispMessage {

	public:

		CrispMessage() : header_(), payload_data_(), base_key_(), k_enc_(), k_mac_(), icv_() {
		}

		void set_header(const std::vector<uint8_t>& header) {
			header_.resize(header.size());
			std::copy(header.begin(), header.end(), header_.begin());
		}

		void set_payload(const std::vector<uint8_t>& payload) {
			payload_data_.resize(payload.size());
			std::copy(payload.begin(), payload.end(), payload_data_.begin());
		}

		std::vector<uint8_t> get_payload() {
			std::vector<uint8_t> pld(payload_data_.size());
			std::copy(payload_data_.begin(), payload_data_.end(), pld.begin());
			return pld;
		}

		void set_baseKey(const std::vector<uint8_t>& baseKey) {
			base_key_.resize(baseKey.size());
			std::copy(baseKey.begin(), baseKey.end(), base_key_.begin());
		}

		void set_k_enc(const std::vector<uint8_t>& k_enc) {
			k_enc_.resize(k_enc.size());
			std::copy(k_enc.begin(), k_enc.end(), k_enc_.begin());
		}

		void set_k_mac(const std::vector<uint8_t>& k_mac) {
			k_mac_.resize(k_mac.size());
			std::copy(k_mac.begin(), k_mac.end(), k_mac_.begin());
		}

		void set_icv(const std::vector<uint8_t>& icv) {
			icv_.resize(icv.size());
			std::copy(icv.begin(), icv.end(), icv_.begin());
		}

		std::string to_string() {
			return "---Crisp Message---\nheader: " +
				vector_to_hex_str(header_) + "\n" +
				"payload: " + vector_to_hex_str(payload_data_) + "\n" +
				"baseKey: " + vector_to_hex_str(base_key_) + "\n" +
				"kEnc: " + vector_to_hex_str(k_enc_) + "\n" +
				"kMac: " + vector_to_hex_str(k_mac_) + "\n" +
				"ICV: " + vector_to_hex_str(icv_) + "\n";
		}

	private:

		std::vector<uint8_t> header_;

		std::vector<uint8_t> payload_data_;

		std::vector<uint8_t> base_key_;

		std::vector<uint8_t> k_enc_;

		std::vector<uint8_t> k_mac_;

		std::vector<uint8_t> icv_;

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

} // namespace ProtoQa

#endif // REFERENCEIMPLEMENTATIONS_CRISPMESSAGE_H