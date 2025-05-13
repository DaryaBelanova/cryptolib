#include "HMAC256.h"
#include <iostream>
#include <iomanip>

namespace HMAC {

	HMAC256::HMAC256(const std::vector<uint8_t>& key) {
		refresh(key);
	}

	void HMAC256::update(const std::vector<uint8_t>& m) {
		std::vector<uint8_t> reversed_bytes(m.size());
		std::copy(m.rbegin(), m.rend(), reversed_bytes.begin());
		streebog256_.update(reversed_bytes);
	}

	void HMAC256::finalize(std::vector<uint8_t>& dst) {
		//streebog256_.update(k_ipad_);
		std::vector<uint8_t> h1 = {};
		streebog256_.finalize(h1);

		streebog256_.refresh();
		// k_opad first, h2 second because of little endian byte string
		streebog256_.update(k_opad_);
		streebog256_.update(h1);
		//streebog256_.update(k_opad_);
		std::vector<uint8_t> h2 = {};
		streebog256_.finalize(h2);

		dst.resize(h2.size());
		std::copy(h2.rbegin(), h2.rend(), dst.begin());
	}

	// reset streebog inner state and fill k xor ipad and k xor opad fields with new key
	void HMAC256::refresh(const std::vector<uint8_t>& new_key) {
		k_ipad_.resize(64);
		std::copy(new_key.rbegin(), new_key.rend(), k_ipad_.begin() + (64 - new_key.size()));
		for (int i = 0; i < 64; i++) {
			k_ipad_[i] ^= 0x36;
		}

		k_opad_.resize(64);
		std::copy(new_key.rbegin(), new_key.rend(), k_opad_.begin() + (64 - new_key.size()));
		for (int i = 0; i < 64; i++) {
			k_opad_[i] ^= 0x5c;
		}

		streebog256_.refresh();
		streebog256_.update(k_ipad_); // first part of byte string (first because of little endian)
	}

	// reset streebog inner state. Does not change key-dependent fields (k xor ipad, k xor opad)
	void HMAC256::refresh() {
		streebog256_.refresh();
		streebog256_.update(k_ipad_); // first part of byte string
	}

} // namespace HMAC 