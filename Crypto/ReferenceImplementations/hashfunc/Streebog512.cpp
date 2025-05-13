#include "Streebog512.h"\

namespace HashFunc {

	Streebog512::Streebog512() {
		iv_.fill(0);
		h_ = {};
		std::copy(iv_.begin(), iv_.end(), h_.begin());
	}

	void Streebog512::finalize(std::vector<uint8_t>& dst) {
		std::array<uint8_t, byte_block_size> h = {};
		Streebog::finalize(h);
		dst.resize(byte_block_size);
		std::copy(h.begin(), h.end(), dst.begin());
	}

	void Streebog512::refresh() {
		Streebog::refresh();
		std::copy(iv_.begin(), iv_.end(), h_.begin());
	}

} // namespace HashFunc