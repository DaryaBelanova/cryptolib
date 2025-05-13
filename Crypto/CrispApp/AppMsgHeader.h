#ifndef REFERENCEIMPLEMENTATIONS_APPMSGHEADER_H
#define REFERENCEIMPLEMENTATIONS_APPMSGHEADER_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>



	class AppMsgHeader {

	public:

		AppMsgHeader() : Ver_(1), SenderId_(16), RecipientId_(16), SessionId_(4), MsgType_(1), HeaderFlags_(1), TimeStamp_(8) {

			Ver_[0] = 0x00; // default value
			std::fill(TimeStamp_.begin(), TimeStamp_.end(), 0x00);

		}

		void set_Ver(const std::vector<uint8_t>& ver) {
			Ver_[0] = ver[0];
		}
		void set_SenderID(const std::vector<uint8_t>& senderId) {
			std::copy(senderId.begin(), senderId.end(), SenderId_.begin());
		}
		void set_RecipientId(const std::vector<uint8_t>& recipientId) {
			std::copy(recipientId.begin(), recipientId.end(), RecipientId_.begin());
		}
		void set_SessionId(const std::vector<uint8_t>& sessionId) {
			std::copy(sessionId.begin(), sessionId.end(), SessionId_.begin());
		}
		void set_MsgType(const std::vector<uint8_t>& msgType) {
			MsgType_[0] = msgType[0];
		}
		void set_HeaderFlags(const std::vector<uint8_t>& headerFlags) {
			HeaderFlags_[0] = headerFlags[0];
		}
		void set_TimeStamp(const std::vector<uint8_t>& timeStamp) {
			std::copy(timeStamp.begin(), timeStamp.end(), TimeStamp_.begin());
		}

		std::vector<uint8_t> get_bytes() {
			std::vector<uint8_t> dst;
			dst.insert(dst.end(), Ver_.begin(), Ver_.end());
			dst.insert(dst.end(), SenderId_.begin(), SenderId_.end());
			dst.insert(dst.end(), RecipientId_.begin(), RecipientId_.end());
			dst.insert(dst.end(), SessionId_.begin(), SessionId_.end());
			dst.insert(dst.end(), MsgType_.begin(), MsgType_.end());
			dst.insert(dst.end(), HeaderFlags_.begin(), HeaderFlags_.end());
			dst.insert(dst.end(), TimeStamp_.begin(), TimeStamp_.end());

			return dst;
		}

		std::string to_string() {
			return "--- Header ---\nVer: " +
				vector_to_hex_str(Ver_) + "\n" +
				"SenderID: " + vector_to_hex_str(SenderId_) + "\n" +
				"RecipientID: " + vector_to_hex_str(RecipientId_) + "\n" +
				"SessionID: " + vector_to_hex_str(SessionId_) + "\n" +
				"MsgType: " + vector_to_hex_str(MsgType_) + "\n" +
				"HeaderFlags: " + vector_to_hex_str(HeaderFlags_) + "\n" +
				"TimeStamp: " + vector_to_hex_str(TimeStamp_) + "\n";
		}

	private:

		std::vector<uint8_t> Ver_; // 1 byte

		std::vector<uint8_t> SenderId_; // 16 bytes

		std::vector<uint8_t> RecipientId_; // 16 bytes

		std::vector<uint8_t> SessionId_; // 4 bytes

		std::vector<uint8_t> MsgType_; // 1 byte

		std::vector<uint8_t> HeaderFlags_; // 1 byte

		std::vector<uint8_t> TimeStamp_; // 8 byte

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

#endif // REFERENCEIMPLEMENTATIONS_APPMSGHEADER_H