#include <array>
#include "CrispDriver.h"
#include "CrispSuiteFactory.h"

namespace Crisp {

	CrispDriver::CrispDriver() : suite_(nullptr), KeyId_(), accepted_messages_range_(), SeqNum_(6), Version_(2) {

	}

	CrispDriver::~CrispDriver() {

	}

	void CrispDriver::increment_SeqNum() {
		uint8_t carry = 0;
		uint16_t total = SeqNum_[5] + 1 + carry;
		SeqNum_[5] = total & 0xFF;
		carry = (total >> 8) & 0xFF;
		for (int i = 4; i >= 0; --i) {
			total = SeqNum_[i] + carry;
			SeqNum_[i] = total & 0xFF;
			carry = (total >> 8) & 0xFF;
		}
	}

	uint64_t CrispDriver::SeqNum_to_uint64_t(const std::vector<uint8_t>& seqNumVec) {
		uint64_t seqNum = 0;
		for (int i = 0; i < 6; i++) {
			seqNum |= (static_cast<uint64_t>(seqNumVec[i]) << (8 * (5 - i)));
		}
		return seqNum;
	}

	// whole inner state including suite must be preconfigured
	void CrispDriver::send(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& crispMsg) {
		if (!suite_) {
			throw "CRISP cryptographic suite must be configured.";
		}

		crispMsg = {};

		accepted_messages_range_[SeqNum_to_uint64_t(SeqNum_)] = true;

		uint8_t externalKeyIdFlag_and_version_first_part = ExternalKeyIdFlag_ == 1 ? 0x80 : 0x00;
		uint8_t version_second_part = Version_[1];
		crispMsg.push_back(externalKeyIdFlag_and_version_first_part);
		crispMsg.push_back(version_second_part);

		crispMsg.push_back(CS_);

		crispMsg.insert(crispMsg.end(), KeyId_.begin(), KeyId_.end());

		crispMsg.insert(crispMsg.end(), SeqNum_.begin(), SeqNum_.end());

		if (suite_->is_encryption_provided()) {
			std::vector<uint8_t> encypted_data = {};
			suite_->encrypt(payloadData, encypted_data);
			crispMsg.insert(crispMsg.end(), encypted_data.begin(), encypted_data.end());
		}
		else {
			crispMsg.insert(crispMsg.end(), payloadData.begin(), payloadData.end());
		}

		std::vector<uint8_t> mac;
		suite_->calculate_mac(crispMsg, mac);
		crispMsg.insert(crispMsg.end(), mac.begin(), mac.end());

		increment_SeqNum();
	}

	void CrispDriver::send(const std::vector<uint8_t>& payloadData, CrispMessage& crispMsg) {
		if (!suite_) {
			throw "CRISP cryptographic suite must be configured.";
		}

		accepted_messages_range_[SeqNum_to_uint64_t(SeqNum_)] = true;

		crispMsg.set_k_enc(suite_->get_k_enc());
		crispMsg.set_k_mac(suite_->get_k_mac());

		std::vector<uint8_t> header = {};

		uint8_t externalKeyIdFlag_and_version_first_part = ExternalKeyIdFlag_ == 1 ? 0x80 : 0x00;
		uint8_t version_second_part = Version_[1];
		header.push_back(externalKeyIdFlag_and_version_first_part);
		header.push_back(version_second_part);

		header.push_back(CS_);

		header.insert(header.end(), KeyId_.begin(), KeyId_.end());

		header.insert(header.end(), SeqNum_.begin(), SeqNum_.end());

		crispMsg.set_header(header);

		std::vector<uint8_t> hdr_and_pld(header);
		if (suite_->is_encryption_provided()) {
			std::vector<uint8_t> encypted_data = {};
			suite_->encrypt(payloadData, encypted_data);
			crispMsg.set_payload(encypted_data);
			hdr_and_pld.insert(hdr_and_pld.end(), encypted_data.begin(), encypted_data.end());
		}
		else {
			crispMsg.set_payload(payloadData);
			hdr_and_pld.insert(hdr_and_pld.end(), payloadData.begin(), payloadData.end());
		}

		std::vector<uint8_t> mac;
		suite_->calculate_mac(hdr_and_pld, mac);
		crispMsg.set_icv(mac);

		increment_SeqNum();
	}

	void CrispDriver::receive(const std::vector<uint8_t>& baseKey, const std::vector<uint8_t>& sourceId, int size, const std::vector<uint8_t>& crispData, std::vector<uint8_t>& payloadData) {

		uint8_t externalKeyIdFlag = (crispData[0] & 0x80) ? 1 : 0;

		std::vector<uint8_t> version(2);
		version[0] = (crispData[0] & 0b01111111);
		version[1] = crispData[1];

		uint8_t cs = crispData[2];

		std::vector<uint8_t> keyId;
		size_t idx_after_keyId = 4;
		if (!(crispData[3] == 0x80)) {
			if (crispData[3] & 0x80) {
				uint8_t keyIdSize = crispData[3] & 0b01111111;
				keyId.resize(keyIdSize);
				for (int i = 0; i < keyIdSize; i++) {
					keyId[i] = crispData[idx_after_keyId++];
				}
			}
			else {
				keyId.push_back(crispData[3] & 0b01111111);
			}
		}

		std::vector<uint8_t> seqNum(6);
		for (int i = 0; i < 6; i++) {
			seqNum[i] = crispData[idx_after_keyId++];
		} // here idx_after_keyId is start index of PayloadData

		std::array<uint8_t, 32> key = {};
		std::copy(baseKey.begin(), baseKey.end(), key.begin());
		configure_suite(cs, seqNum, key, sourceId);
		/*if (!suite_) {
			throw "CRISP cryptographic suite must be configured.";
		}*/
		//key.fill(0);

		payloadData = {};
		for (int i = idx_after_keyId; i < crispData.size() - suite_->get_mac_byte_length(); i++) {
			payloadData.push_back(crispData[idx_after_keyId++]);
		} // here idx_after_keId is start of mac

		std::vector<uint8_t> passed_mac(suite_->get_mac_byte_length());
		std::copy(crispData.begin() + idx_after_keyId, crispData.end(), passed_mac.begin());

		std::vector<uint8_t> data_to_check_mac(crispData.size() - suite_->get_mac_byte_length());
		std::copy(crispData.begin(), crispData.begin() + idx_after_keyId, data_to_check_mac.begin());
		std::vector<uint8_t> calculated_mac;
		suite_->calculate_mac(data_to_check_mac, calculated_mac);

		if (calculated_mac != passed_mac) {
			return;
		}

		configure_state(externalKeyIdFlag, keyId, size, seqNum, cs, version);

		uint64_t newSeqNumInt = SeqNum_to_uint64_t(SeqNum_);
		accepted_messages_range_[newSeqNumInt] = true;

		Size_ = Size_ < newSeqNumInt ? newSeqNumInt : Size_;

		if (suite_->is_encryption_provided()) {
			suite_->decrypt(payloadData, payloadData);
		}
	}

	void CrispDriver::configure_suite(uint8_t newCS,
		const std::vector<uint8_t>& newSeqNum,
		const std::array<uint8_t, 32>& newBaseKey,
		const std::vector<uint8_t>& newSourceId) {

		suite_ = CrispSuiteFactory::create_suite(newCS, newSeqNum, newBaseKey, newSourceId);
	}

	void CrispDriver::configure_state(uint8_t externalKeyIdFlag,
		const std::vector<uint8_t>& keyId,
		uint16_t size,
		const std::vector<uint8_t>& seqNum,
		uint8_t CS,
		std::vector<uint8_t> version) {

		ExternalKeyIdFlag_ = externalKeyIdFlag;

		KeyId_.resize(keyId.size());
		std::copy(keyId.begin(), keyId.end(), KeyId_.begin());

		Size_ = size;

		accepted_messages_range_ = {};

		SeqNum_.resize(seqNum.size());
		std::copy(seqNum.begin(), seqNum.end(), SeqNum_.begin());

		CS_ = CS;

		Version_.resize(2);
		std::copy(version.begin(), version.end(), Version_.begin());
	}

	void CrispDriver::configure_state_with_suite(uint8_t externalKeyIdFlag,
		const std::vector<uint8_t>& baseKey,
		const std::vector<uint8_t>& keyId,
		const std::vector<uint8_t>& sourceId,
		uint16_t size,
		const std::vector<uint8_t>& seqNum,
		uint8_t CS,
		std::vector<uint8_t> version) {

		ExternalKeyIdFlag_ = externalKeyIdFlag;

		KeyId_.resize(keyId.size());
		std::copy(keyId.begin(), keyId.end(), KeyId_.begin());

		Size_ = size;

		accepted_messages_range_ = {};

		SeqNum_.resize(seqNum.size());
		std::copy(seqNum.begin(), seqNum.end(), SeqNum_.begin());

		CS_ = CS;

		Version_.resize(2);
		std::copy(version.begin(), version.end(), Version_.begin());


		std::array<uint8_t, 32> baseKeyArr = {};
		std::copy(baseKey.begin(), baseKey.end(), baseKeyArr.begin());

		suite_ = CrispSuiteFactory::create_suite(CS, seqNum, baseKeyArr, sourceId);
	}

} // namespace Crisp