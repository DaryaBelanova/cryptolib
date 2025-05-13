#include "MagmaCTRCMAC.h"

namespace Crisp {

	MagmaCTRCMAC::MagmaCTRCMAC(
		const std::vector<uint8_t>& seqNum,
		const std::array<uint8_t, 32>& baseKey,
		const std::vector<uint8_t>& sourceId) :
		CrispSuite(0x01, 32), // CS = 1, mac_byte_length_ = 32
		kdf_(baseKey),
		iv_(), enc_alg_(get_k_enc(seqNum, sourceId)), enc_mode_(enc_alg_, iv_), mac_alg_(get_k_mac(seqNum, sourceId)), mac_mode_(mac_alg_, mac_byte_length_) {

		k_enc_ = get_k_enc(seqNum, sourceId);
		k_mac_ = get_k_mac(seqNum, sourceId);

		calculate_iv(seqNum);
		enc_mode_.refresh_iv(iv_);
	}

	std::array<uint8_t, 32> MagmaCTRCMAC::get_k_enc(const std::vector<uint8_t>& seqNum,
		const std::vector<uint8_t>& sourceId) {
		std::vector<uint8_t> kEncVec = {};
		kdf_.get_crisp_k_enc(
			{ 0x6d, 0x61, 0x63, 0x65, 0x6e, 0x63 }, // binary('macenc', 6)
			seqNum,
			CS_,
			sourceId,
			512,
			kEncVec);

		std::array<uint8_t, 32> k_enc = {};
		std::copy(kEncVec.begin(), kEncVec.end(), k_enc.begin());

		return k_enc;
	}

	bool MagmaCTRCMAC::is_encryption_provided() {
		return true;
	}

	std::array<uint8_t, 32> MagmaCTRCMAC::get_k_mac(const std::vector<uint8_t>& seqNum,
		const std::vector<uint8_t>& sourceId) {
		std::vector<uint8_t> kMacVec = {};
		kdf_.get_crisp_k_mac(
			{ 0x6d, 0x61, 0x63, 0x65, 0x6e, 0x63 }, // binary('macenc', 6)
			seqNum,
			CS_,
			sourceId,
			512,
			kMacVec);

		std::array<uint8_t, 32> k_mac = {};
		std::copy(kMacVec.begin(), kMacVec.end(), k_mac.begin());

		return k_mac;
	}

	std::vector<uint8_t> MagmaCTRCMAC::get_k_enc() {
		std::vector<uint8_t> kEnc(32);
		std::copy(k_enc_.begin(), k_enc_.end(), kEnc.begin());
		return kEnc;
	}

	std::vector<uint8_t> MagmaCTRCMAC::get_k_mac() {
		std::vector<uint8_t> kMac(32);
		std::copy(k_mac_.begin(), k_mac_.end(), kMac.begin());
		return kMac;
	}

	void MagmaCTRCMAC::calculate_iv(const std::vector<uint8_t>& seqNum) {
		iv_.resize(4);

		iv_[0] = seqNum[2];
		iv_[1] = seqNum[3];
		iv_[2] = seqNum[4];
		iv_[3] = seqNum[5];
	}

	void MagmaCTRCMAC::encrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) {
		enc_mode_.encrypt(payloadData, dst);
	}

	void MagmaCTRCMAC::decrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) {
		enc_mode_.decrypt(payloadData, dst);
	}

	void MagmaCTRCMAC::calculate_mac(const std::vector<uint8_t>& crispMsg, std::vector<uint8_t>& dst) {
		mac_mode_.refresh(mac_byte_length_ * 8);
		mac_mode_.update(crispMsg);
		mac_mode_.finalize(dst);
	}

	bool MagmaCTRCMAC::verify_mac(const std::vector<uint8_t>& crispMsg, const std::vector<uint8_t>& mac) {
		mac_mode_.refresh(mac_byte_length_ * 8);
		mac_mode_.update(crispMsg);
		return mac_mode_.verify(mac);
	}

} // namespace Crisp