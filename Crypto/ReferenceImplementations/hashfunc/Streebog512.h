#ifndef REFERENCEIMPLEMENTATIONS_STREEBOG512_H
#define REFERENCEIMPLEMENTATIONS_STREEBOG512_H

#include "Streebog.h"

namespace HashFunc {

	class Streebog512 : public Streebog {

	public:

		Streebog512();

		void finalize(std::vector<uint8_t>& dst);

		void refresh();

	private:

		std::array<uint8_t, byte_block_size> iv_;
	};

} // namespace HashFunc

#endif //REFERENCEIMPLEMENTATIONS_STREEBOG512_H