#ifndef REFERENCEIMPLEMENTATIONS_NEWKEYREQUEST_H
#define REFERENCEIMPLEMENTATIONS_NEWKEYREQUEST_H

#include "AppMsgPayload.h"
#include <stdint.h>


	class NewKeyRequest : public AppMsgPayload {

	public:

		NewKeyRequest() : PairConId_(16), Flags_(1), Timer_(4), KeySize_(2), CS_KW_(1), KeyLabelSize_(1), KeyLabel_(), AddDataSize_(), AddData_() {

		}

		void set_PairConId(const std::vector<uint8_t>& PairConId) {
			std::copy(PairConId.begin(), PairConId.end(), PairConId_.begin());
		}
		void set_Flags(const std::vector<uint8_t>& Flags) {
			Flags_[0] = Flags[0];
		}
		void set_Timer(const std::vector<uint8_t>& Timer) {
			std::copy(Timer.begin(), Timer.end(), Timer_.begin());
		}
		void set_KeySize(const std::vector<uint8_t>& KeySize) {
			std::copy(KeySize.begin(), KeySize.end(), KeySize_.begin());
		}
		void set_CS_KW(const std::vector<uint8_t>& CS_KW) {
			CS_KW_[0] = CS_KW[0];
		}
		void set_KeyLabelSize(const std::vector<uint8_t>& KeyLabelSize) {
			KeyLabelSize_[0] = KeyLabelSize[0];
		}
		void set_KeyLabel(const std::vector<uint8_t>& KeyLabel) {
			KeyLabel_.resize(KeyLabel.size());
			std::copy(KeyLabel.begin(), KeyLabel.end(), KeyLabel_.begin());
		}
		void set_AddDataSize(const std::vector<uint8_t>& AddDataSize) {
			AddDataSize_.resize(AddDataSize.size());
			std::copy(AddDataSize.begin(), AddDataSize.end(), AddDataSize_.begin());
		}
		void set_AddData(const std::vector<uint8_t>& AddData) {
			AddData_.resize(AddData.size());
			std::copy(AddData.begin(), AddData.end(), AddData_.begin());
		}


		std::vector<uint8_t> get_bytes() override {
			std::vector<uint8_t> dst = {};
			dst.insert(dst.end(), PairConId_.begin(), PairConId_.end());
			dst.insert(dst.end(), Flags_.begin(), Flags_.end());
			dst.insert(dst.end(), Timer_.begin(), Timer_.end());
			dst.insert(dst.end(), KeySize_.begin(), KeySize_.end());
			dst.insert(dst.end(), CS_KW_.begin(), CS_KW_.end());
			dst.insert(dst.end(), KeyLabelSize_.begin(), KeyLabelSize_.end());
			dst.insert(dst.end(), KeyLabel_.begin(), KeyLabel_.end());
			dst.insert(dst.end(), AddDataSize_.begin(), AddDataSize_.end());
			dst.insert(dst.end(), AddData_.begin(), AddData_.end());

			return dst;
		}

		std::string to_string() override {
			return "--- Payload (New Key Request) ---\nPairConId: " +
				vector_to_hex_str(PairConId_) + "\n" +
				"Flags: " + vector_to_hex_str(Flags_) + "\n" +
				"Timer: " + vector_to_hex_str(Timer_) + "\n" +
				"KeySize: " + vector_to_hex_str(KeySize_) + "\n" +
				"CS_KW: " + vector_to_hex_str(CS_KW_) + "\n" +
				"KeyLabelSize: " + vector_to_hex_str(KeyLabelSize_) + "\n" +
				"KeyLabel: " + vector_to_hex_str(KeyLabel_) + "\n" +
				"AddDataSize: " + vector_to_hex_str(AddDataSize_) + "\n" +
				"AddData: " + vector_to_hex_str(AddData_) + "\n";
		}

	private:

		std::vector<uint8_t> PairConId_; // 16 bytes

		std::vector<uint8_t> Flags_; // 1 byte

		std::vector<uint8_t> Timer_; // 4 bytes

		std::vector<uint8_t> KeySize_; // 2 bytes

		std::vector<uint8_t> CS_KW_; // 1 byte

		std::vector<uint8_t> KeyLabelSize_; // 1 byte

		std::vector<uint8_t> KeyLabel_; // determined by KeyLabelSize and does not exceed 255 bytes

		std::vector<uint8_t> AddDataSize_; // 2 bytes

		std::vector<uint8_t> AddData_; // determined by AddDataSize
	};


#endif //REFERENCEIMPLEMENTATIONS_NEWKEYREQUEST_H