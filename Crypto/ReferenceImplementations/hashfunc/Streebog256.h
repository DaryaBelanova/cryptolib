#ifndef REFERENCEIMPLEMENTATIONS_STREEBOG256_H
#define REFERENCEIMPLEMENTATIONS_STREEBOG256_H

#include "Streebog.h"

namespace HashFunc {

	class Streebog256 : public Streebog {

	public:

		Streebog256();

		void finalize(std::vector<uint8_t>& dst);

		void refresh();

	private:

		std::array<uint8_t, byte_block_size> iv_;
	};

} // namespace HashFunc

#endif //REFERENCEIMPLEMENTATIONS_STREEBOG256_H