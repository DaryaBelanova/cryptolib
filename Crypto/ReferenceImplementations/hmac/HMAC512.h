#ifndef REFERENCEIMPLEMENTATIONS_HMAC512_H
#define REFERENCEIMPLEMENTATIONS_HMAC512_H

#include <vector>
#include "../hashfunc/Streebog512.h"

using namespace HashFunc;

namespace HMAC {

	// in GOST input byte strings are in little endian order
	// calculated HMAC is also required in little endian byte order

	class HMAC512 {

	public:

		HMAC512(const std::vector<uint8_t>& key);

		void update(const std::vector<uint8_t>& m);

		void finalize(std::vector<uint8_t>& dst);

		void refresh(const std::vector<uint8_t>& new_key);

		void refresh();

	private:

		Streebog512 streebog512_;

		std::vector<uint8_t> k_ipad_;

		std::vector<uint8_t> k_opad_;
	};

} // namespace HMAC

#endif // REFERENCEIMPLEMENTATIONS_HMAC512_H