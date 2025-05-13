#include "MagmaNullCMAC8.h"

namespace Crisp {

	MagmaNullCMAC8::MagmaNullCMAC8(
		const std::vector<uint8_t>& seqNum,
		const std::array<uint8_t, 32>& baseKey,
		const std::vector<uint8_t>& sourceId) :
		CrispSuite(0x04, 64), // CS = 4, mac_byte_length_ = 64
		kdf_(baseKey), mac_alg_(get_k_mac(seqNum, sourceId)), mac_mode_(mac_alg_, mac_byte_length_) {

		k_mac_ = get_k_mac(seqNum, sourceId);
	}

	bool MagmaNullCMAC8::is_encryption_provided() {
		return false;
	}

	std::array<uint8_t, 32> MagmaNullCMAC8::get_k_enc(const std::vector<uint8_t>& seqNum,
		const std::vector<uint8_t>& sourceId) {

		throw "Not supported.";
	}

	std::array<uint8_t, 32> MagmaNullCMAC8::get_k_mac(const std::vector<uint8_t>& seqNum,
		const std::vector<uint8_t>& sourceId) {
		std::vector<uint8_t> kMacVec = {};
		kdf_.get_crisp_k_mac(
			{ 0x6d, 0x61, 0x63, 0x6d, 0x61, 0x63 }, // binary('macmac', 6)
			seqNum,
			CS_,
			sourceId,
			256,
			kMacVec);

		std::array<uint8_t, 32> k_mac = {};
		std::copy(kMacVec.begin(), kMacVec.end(), k_mac.begin());

		return k_mac;
	}

	std::vector<uint8_t> MagmaNullCMAC8::get_k_enc() {
		return {};
	}

	std::vector<uint8_t> MagmaNullCMAC8::get_k_mac() {
		std::vector<uint8_t> kMac(32);
		std::copy(k_mac_.begin(), k_mac_.end(), kMac.begin());
		return kMac;
	}

	void MagmaNullCMAC8::calculate_iv(const std::vector<uint8_t>& seqNum) {

		throw "Not supported.";
	}

	void MagmaNullCMAC8::encrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) {

		throw "Not supported.";
	}

	void MagmaNullCMAC8::decrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) {

		throw "Not supported.";
	}

	void MagmaNullCMAC8::calculate_mac(const std::vector<uint8_t>& crispMsg, std::vector<uint8_t>& dst) {
		mac_mode_.refresh(mac_byte_length_ * 8);
		mac_mode_.update(crispMsg);
		mac_mode_.finalize(dst);
	}

	bool MagmaNullCMAC8::verify_mac(const std::vector<uint8_t>& crispMsg, const std::vector<uint8_t>& mac) {
		mac_mode_.refresh(mac_byte_length_ * 8);
		mac_mode_.update(crispMsg);
		return mac_mode_.verify(mac);
	}

} // namespace Crisp