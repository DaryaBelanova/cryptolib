#include "HMAC512.h"
#include <iostream>
#include <iomanip>

namespace HMAC {

	HMAC512::HMAC512(const std::vector<uint8_t>& key) {
		refresh(key);
	}

	void HMAC512::update(const std::vector<uint8_t>& m) {
		std::vector<uint8_t> reversed_bytes(m.size());
		std::copy(m.rbegin(), m.rend(), reversed_bytes.begin());
		streebog512_.update(reversed_bytes);
	}

	void HMAC512::finalize(std::vector<uint8_t>& dst) {
		//streebog512_.update(k_ipad_);
		std::vector<uint8_t> h1 = {};
		streebog512_.finalize(h1);

		streebog512_.refresh();
		streebog512_.update(k_opad_);
		streebog512_.update(h1);
		//streebog512_.update(k_opad_);
		std::vector<uint8_t> h2 = {};
		streebog512_.finalize(h2);

		dst.resize(h2.size());
		std::copy(h2.rbegin(), h2.rend(), dst.begin());
	}

	// reset streebog inner state and fill k xor ipad and k xor opad fields with new key
	void HMAC512::refresh(const std::vector<uint8_t>& new_key) {
		k_ipad_.resize(64);
		std::cout << '\n';
		std::copy(new_key.rbegin(), new_key.rend(), k_ipad_.begin() + (64 - new_key.size()));
		for (int i = 0; i < 64; i++) {
			k_ipad_[i] ^= 0x36;
		}

		k_opad_.resize(64);
		std::copy(new_key.rbegin(), new_key.rend(), k_opad_.begin() + (64 - new_key.size()));
		for (int i = 0; i < 64; i++) {
			k_opad_[i] ^= 0x5c;
		}

		streebog512_.refresh();
		streebog512_.update(k_ipad_);
	}

	// reset streebog inner state. Does not change key-dependent fields (k xor ipad, k xor opad)
	void HMAC512::refresh() {
		streebog512_.refresh();
		streebog512_.update(k_ipad_);
	}

} // namespace HMAC