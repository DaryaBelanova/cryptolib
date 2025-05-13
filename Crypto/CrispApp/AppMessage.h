#ifndef REFERENCEIMPLEMENTATIONS_APPMESSAGE_H
#define REFERENCEIMPLEMENTATIONS_APPMESSAGE_H

#include "AppMsgHeader.h"
#include "AppMsgPayload.h"
#include "../crisp/CrispDriver.h"
#include "../crisp/CrispMessage.h"

	template<typename AppMsgPayloadType>
	class AppMessage {

	public:

		AppMessage(AppMsgHeader& header, AppMsgPayloadType& payload) : header_(header), payload_(payload), crisp_msg_() {

		}

		std::vector<uint8_t> get_bytes() {
			std::vector<uint8_t> dst = header_.get_bytes();
			std::vector<uint8_t> to_insert = payload_.get_bytes();
			dst.insert(dst.end(), to_insert.begin(), to_insert.end());

			return dst;
		}

		std::vector<uint8_t> get_crisp_msg_bytes() {
			std::vector<uint8_t> dst(crisp_msg_);

			return dst;
		}

		void make_crisp(uint8_t externalKeyIdFlag,
			const std::vector<uint8_t>& baseKey,
			const std::vector<uint8_t>& keyId,
			const std::vector<uint8_t>& sourceId,
			uint16_t size,
			const std::vector<uint8_t>& seqNum,
			uint8_t CS,
			std::vector<uint8_t> version) {

			Crisp::CrispDriver crispDriver;
			crispDriver.configure_state_with_suite(externalKeyIdFlag, baseKey, keyId, sourceId, size, seqNum, CS, version);
			crispDriver.send(get_bytes(), crisp_msg_);
		}

		void make_crisp(Crisp::CrispMessage& msg, 
			uint8_t externalKeyIdFlag,
			const std::vector<uint8_t>& baseKey,
			const std::vector<uint8_t>& keyId,
			const std::vector<uint8_t>& sourceId,
			uint16_t size,
			const std::vector<uint8_t>& seqNum,
			uint8_t CS,
			std::vector<uint8_t> version) {

			Crisp::CrispDriver crispDriver;
			crispDriver.configure_state_with_suite(externalKeyIdFlag, baseKey, keyId, sourceId, size, seqNum, CS, version);
			msg.set_baseKey(baseKey);
			crispDriver.send(get_bytes(), msg);
		}

		std::string to_string() {
			std::string payload_type_name = typeid(AppMsgPayloadType).name();
			return "--- App Message (" + payload_type_name + ") ---\n" +
				vector_to_hex_str(crisp_msg_) + "\n";
		}

	private:

		AppMsgHeader header_;

		AppMsgPayloadType payload_;

		std::vector<uint8_t> crisp_msg_;

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

#endif // REFERENCEIMPLEMENTATIONS_APPMESSAGE_H