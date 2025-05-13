#include "Streebog256.h"

namespace HashFunc {

	Streebog256::Streebog256() {
		iv_.fill(1);
		h_ = {};
		std::copy(iv_.begin(), iv_.end(), h_.begin());
	}


	void Streebog256::finalize(std::vector<uint8_t>& dst) {

		std::array<uint8_t, byte_block_size> h = {};
		Streebog::finalize(h);
		dst.resize(byte_block_size / 2);
		std::copy(h.begin(), h.begin() + byte_block_size / 2, dst.begin());
	}

	void Streebog256::refresh() {
		Streebog::refresh();
		std::copy(iv_.begin(), iv_.end(), h_.begin());
	}

} // namespace HashFunc