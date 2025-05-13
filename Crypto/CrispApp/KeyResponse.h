#ifndef REFERENCEIMPLEMENTATIONS_KEYRESPONSE_H
#define REFERENCEIMPLEMENTATIONS_KEYRESPONSE_H

#include "AppMsgPayload.h"
#include "../kexp15kimp15/KExp15.h"
#include "../ciphersuite/Kuznyechik.h"
#include "../ciphersuite/Magma.h"

using namespace EncryptionAlgorithms;



	class KeyResponse : public AppMsgPayload {

	public:

		KeyResponse() : PairConId_(16), Flags_(1), TargetKeyId_(40), KeySize_(2), CS_KW_(1), KeyLabelSize_(1), KeyLabel_(), KeyContainer_(), AddDataSize_(), AddData_() {

		}

		void set_PairConId(const std::vector<uint8_t>& PairConId) {
			std::copy(PairConId.begin(), PairConId.end(), PairConId_.begin());
		}
		void set_Flags(const std::vector<uint8_t>& Flags) {
			Flags_[0] = Flags[0];
		}
		void set_TargetKeyId(const std::vector<uint8_t>& TargetKeyId) {
			std::copy(TargetKeyId.begin(), TargetKeyId.end(), TargetKeyId_.begin());
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
		/*void set_KeyContainer(const std::vector<uint8_t> &KeyWrapId, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& key) {
			KeyContainer_.insert(KeyContainer_.end(), KeyWrapId.begin(), KeyWrapId.end());
			KeyContainer_.insert(KeyContainer_.end(), IV.begin(), IV.end());

		}*/
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
			dst.insert(dst.end(), TargetKeyId_.begin(), TargetKeyId_.end());
			dst.insert(dst.end(), KeySize_.begin(), KeySize_.end());
			dst.insert(dst.end(), CS_KW_.begin(), CS_KW_.end());
			dst.insert(dst.end(), KeyLabelSize_.begin(), KeyLabelSize_.end());
			dst.insert(dst.end(), KeyLabel_.begin(), KeyLabel_.end());
			dst.insert(dst.end(), KeyContainer_.begin(), KeyContainer_.end());
			dst.insert(dst.end(), AddDataSize_.begin(), AddDataSize_.end());
			dst.insert(dst.end(), AddData_.begin(), AddData_.end());

			return dst;
		}

		void make_KeyContainer_exp(const std::vector<uint8_t>& CS_KW,
			const std::vector<uint8_t>& key,
			const std::vector<uint8_t>& k_mac,
			const std::vector<uint8_t>& k_enc,
			const std::vector<uint8_t>& keyWrapId,
			const std::vector<uint8_t>& iv) {

			std::array<uint8_t, 32> k_mac_arr = {};
			std::copy(k_mac.begin(), k_mac.end(), k_mac_arr.begin());
			std::array<uint8_t, 32> k_enc_arr = {};
			std::copy(k_enc.begin(), k_enc.end(), k_enc_arr.begin());

			switch (CS_KW[0]) {
			case 0x01:
				KExp15<Kuznyechik> kexp_kuz;
				kexp_kuz.export_key(key, k_mac_arr, k_enc_arr, iv, KeyContainer_);
				break;

			case 0x02:
				KExp15<Magma> kexp_magma;
				kexp_magma.export_key(key, k_mac_arr, k_enc_arr, iv, KeyContainer_);
				break;

			default:
				throw "Invalid CS_KW.";
			}

			KeyContainer_.insert(KeyContainer_.begin(), iv.begin(), iv.end());
			KeyContainer_.insert(KeyContainer_.begin(), keyWrapId.begin(), keyWrapId.end());
		}



		std::string to_string() override {
			return "--- Payload (Key Response) ---\nPairConId: " +
				vector_to_hex_str(PairConId_) + "\n" +
				"Flags: " + vector_to_hex_str(Flags_) + "\n" +
				"TargetKeyId: " + vector_to_hex_str(TargetKeyId_) + "\n" +
				"KeySize: " + vector_to_hex_str(KeySize_) + "\n" +
				"CS_KW: " + vector_to_hex_str(CS_KW_) + "\n" +
				"KeyLabelSize: " + vector_to_hex_str(KeyLabelSize_) + "\n" +
				"KeyLabel: " + vector_to_hex_str(KeyLabel_) + "\n" +
				"KeyContainer: " + vector_to_hex_str(KeyContainer_) + "\n" +
				"AddDataSize: " + vector_to_hex_str(AddDataSize_) + "\n" +
				"AddData: " + vector_to_hex_str(AddData_) + "\n";
		}

	private:

		std::vector<uint8_t> PairConId_; // 16 bytes

		std::vector<uint8_t> Flags_; // 1 byte

		std::vector<uint8_t> TargetKeyId_; // 40 bytes

		std::vector<uint8_t> KeySize_; // 2 bytes

		std::vector<uint8_t> CS_KW_; // 1 byte

		std::vector<uint8_t> KeyLabelSize_; // 1 byte

		std::vector<uint8_t> KeyLabel_; // determined by KeyLabelSize and does not exceed 255 bytes

		std::vector<uint8_t> KeyContainer_; // depends on KeySize and CS_KW

		std::vector<uint8_t> AddDataSize_; // 2 bytes

		std::vector<uint8_t> AddData_; // determined by AddDataSize

	};
#endif //REFERENCEIMPLEMENTATIONS_KEYRESPONSE_H