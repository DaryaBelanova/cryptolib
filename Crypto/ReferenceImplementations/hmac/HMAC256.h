#ifndef REFERENCEIMPLEMENTATIONS_HMAC256_H
#define REFERENCEIMPLEMENTATIONS_HMAC256_H

#include <vector>
#include "../hashfunc/Streebog256.h"

using namespace HashFunc;

namespace HMAC {

	// in GOST input byte strings are in little endian order
	// calculated HMAC is also required in little endian byte order

	class HMAC256 {

	public:

		HMAC256(const std::vector<uint8_t>& key);

		void update(const std::vector<uint8_t>& m);

		void finalize(std::vector<uint8_t>& dst);

		void refresh(const std::vector<uint8_t>& new_key);

		void refresh();

	private:

		Streebog256 streebog256_;

		std::vector<uint8_t> k_ipad_;

		std::vector<uint8_t> k_opad_;
	};

} // namespace HMAC

#endif // REFERENCEIMPLEMENTATIONS_HMAC256_H