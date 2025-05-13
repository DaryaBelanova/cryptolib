#ifndef REFERENCEIMPLEMENTATIONS_KDF_H
#define REFERENCEIMPLEMENTATIONS_KDF_H

#include <vector>
#include <stdint.h>
#include <cmath>
#include <iostream>
#include <iomanip>
#include "../hmac/HMAC256.h"
#include "../ciphermodes/CMAC.h"
#include "../ciphersuite/Magma.h"
#include "../ciphersuite/Kuznyechik.h"

using namespace CipherModes;
using namespace HMAC;


	template <typename PrfType>
	class KDF;

	// HMAC256 specialization
	template<>
	class KDF<HMAC256> {

	public:

		KDF(const std::vector<uint8_t>& key, uint8_t R, uint64_t L) : hmac256_(key) {
			if (R > 4 || R < 1) {
				throw "Incorrect GOST KDF_TREE R parameter. Must be 1, 2, 3 or 4.";
			}
			if (L < 0 || L >(256 * (std::pow(2, 8 * R) - 1))) {
				throw "Incorrect GOST KDF_TREE L parameter. Must not be greater than 256*(2^(8R) - 1). ";
			}
			counter_.resize(R);

			for (int i = 4; i >= 0; --i) { // little endian of uint64_t to big endian of vector<uint8_t>
				uint8_t byte = (L >> (i * 8)) & 0xFF;
				if (L_byte_representation.empty() && byte == 0) {
					continue;
				}
				L_byte_representation.push_back(byte);
			}
			if (L_byte_representation.empty()) {
				L_byte_representation.push_back(0);
			}
		}

		// refresh inners state of inner hmac256_
		void get_ki(uint64_t i,
			const std::vector<uint8_t>& label, // in little endian (P 50.1.113-2016)
			const std::vector<uint8_t>& seed,  // in little endian (P 50.1.113-2016)
			std::vector<uint8_t>& dst) {  // required in little endian (P 50.1.113-2016) 

			for (int j = 0; j < counter_.size(); j++) {
				counter_[j] = i & (0xff >> j * 8);
			}

			// hmac is waiting for little endian GOST byte string (exactly as in GOST formula)

			hmac256_.update(counter_); // [i]b

			hmac256_.update(label); // [i]b | label

			hmac256_.update({ 0x00 }); // [i]b | label | 0x00

			hmac256_.update(seed); // [i]b | label | 0x00 | seed 

			hmac256_.update(L_byte_representation); // [i]b | label | 0x00 | seed | [L]b

			hmac256_.finalize(dst);
			hmac256_.refresh();
		}

		void get_k_seq(uint64_t i,
			const std::vector<uint8_t>& label,
			const std::vector<uint8_t>& seed,
			std::vector<uint8_t>& dst) {

			std::vector<uint8_t> kj = {};
			for (uint64_t j = 1; j <= i; ++j) {
				get_ki(j, label, seed, kj);
				dst.insert(dst.end(), kj.begin(), kj.end());
			}
		}

	private:

		HMAC256 hmac256_;

		std::vector<uint8_t> counter_; // in big endian byte order

		std::vector<uint8_t> L_byte_representation; // in big endian order

	};

	// CMAC CRISP specialization (big endian according GOST P 71252-2024). Allowed both Magma or Kuznyechik as CipherType parameter.
	template<typename CipherType>
	class KDF<CMAC<CipherType>> {

	public:

		KDF(const std::array<uint8_t, 32>& key) : alg_(key), cmac_(alg_, CipherType::byte_block_size * 8) {
			ki_count = 32 / CipherType::byte_block_size;
		}

		/*KDF(const std::array<uint8_t, 32>& key) : cmac_(key, CipherType::byte_block_size * 8), ki_count(32 / CipherType::byte_block_size) {

		}*/

		void get_crisp_k_mac(
			const std::vector<uint8_t>& label,
			const std::vector<uint8_t>& seqNum, // 6 bytes
			uint8_t CS,
			const std::vector<uint8_t>& sourceId,
			uint16_t outputLength,
			std::vector<uint8_t>& dst) {

			std::vector<uint8_t> ki = {};
			for (int i = 1; i <= ki_count; ++i) { // 256 bit / 64 bit or 256 bit / 128 bit
				get_crisp_ki(i, label, seqNum, CS, sourceId, outputLength, ki);
				dst.insert(dst.end(), ki.begin(), ki.end());
			}
		}

		void get_crisp_k_enc(
			const std::vector<uint8_t>& label,
			const std::vector<uint8_t>& seqNum, // 6 bytes
			uint8_t CS,
			const std::vector<uint8_t>& sourceId,
			uint16_t outputLength,
			std::vector<uint8_t>& dst) {

			std::vector<uint8_t> ki = {};
			for (int i = ki_count + 1; i <= 2 * ki_count; ++i) {
				get_crisp_ki(i, label, seqNum, CS, sourceId, outputLength, ki);
				dst.insert(dst.end(), ki.begin(), ki.end());
			}
		}

		void refresh_key(const std::array<uint8_t, 32>& newKey) {
			alg_.refresh_iter_key(newKey);
			cmac_.refresh(CipherType::byte_block_size * 8);
			ki_count = 0;
		}

	private:

		CipherType alg_;

		CMAC<CipherType> cmac_;

		size_t ki_count;

		void get_crisp_ki(int i,
			const std::vector<uint8_t>& label,
			const std::vector<uint8_t>& seqNum, // 6 bytes
			uint8_t CS,
			const std::vector<uint8_t>& sourceId,
			uint16_t outputLength,
			std::vector<uint8_t>& dst) {

			cmac_.refresh(64);

			std::vector<uint8_t> byte_i_1 = { (uint8_t)(i | 0x00) };
			std::vector<uint8_t> aL = { 0x06 };
			std::vector<uint8_t> SN(5);
			SN[0] |= seqNum[0] >> 5;
			SN[1] = (seqNum[0] << 3) | (seqNum[1] >> 5);
			SN[2] = (seqNum[1] << 3) | (seqNum[2] >> 5);
			SN[3] = (seqNum[2] << 3) | (seqNum[3] >> 5);
			SN[4] = (seqNum[3] << 3) | (seqNum[4] >> 5);
			std::vector<uint8_t> CS_vec = { CS };
			std::vector<uint8_t> cL_vec = { 0x00, (uint8_t)(6 + sourceId.size()) };

			std::vector<uint8_t> oL = { ((uint8_t)((outputLength >> 8) | 0x00)), ((uint8_t)(outputLength | 0x00)) }; // uint16_t in little endian

			cmac_.update(byte_i_1);
			cmac_.update(label);
			cmac_.update(aL);
			cmac_.update(SN);
			cmac_.update(sourceId);
			cmac_.update(CS_vec);
			cmac_.update(cL_vec);
			cmac_.update(oL);


			cmac_.finalize(dst);

			cmac_.refresh(CipherType::byte_block_size * 8);
		}

	};



#endif // REFERENCEIMPLEMENTATIONS_KDF_H