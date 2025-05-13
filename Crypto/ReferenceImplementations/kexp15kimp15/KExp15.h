#ifndef REFERENCEIMPLEMENTATIONS_KEXP15_H
#define REFERENCEIMPLEMENTATIONS_KEXP15_H

#include <vector>
#include <array>
#include "../ciphermodes/CMAC.h"
#include "../ciphermodes/CTR.h"

using namespace CipherModes;


	template <typename CipherType>
	class KExp15 {

	public:

		void export_key(const std::vector<uint8_t>& key,
			const std::array<uint8_t, 32>& k_mac,
			const std::array<uint8_t, 32>& k_enc,
			const std::vector<uint8_t>& iv,
			std::vector<uint8_t>& dst);

		void import_key(const std::vector<uint8_t>& kexp,
			const std::array<uint8_t, 32>& k_mac,
			const std::array<uint8_t, 32>& k_enc,
			const std::vector<uint8_t>& iv,
			std::vector<uint8_t>& dst);

		friend class KExp15Test;

	};

	template<typename CipherType>
	void KExp15<CipherType>::export_key(const std::vector<uint8_t>& key,
		const std::array<uint8_t, 32>& k_mac,
		const std::array<uint8_t, 32>& k_enc,
		const std::vector<uint8_t>& iv,
		std::vector<uint8_t>& dst) {

		CipherType alg_mac(k_mac);
		CMAC<CipherType> cmac(alg_mac, CipherType::byte_block_size * 8);
		//CMAC<CipherType> cmac(k_mac, CipherType::byte_block_size * 8);
		CipherType alg_enc(k_enc);
		CTR<CipherType> ctr(alg_enc, iv);
		//CTR<CipherType> ctr(k_enc, iv);

		cmac.update(iv);
		cmac.update(key);

		std::vector<uint8_t> src;
		cmac.finalize(src);

		src.insert(src.begin(), key.begin(), key.end());

		ctr.encrypt(src, dst);
	}

	template<typename CipherType>
	void KExp15<CipherType>::import_key(const std::vector<uint8_t>& kexp,
		const std::array<uint8_t, 32>& k_mac,
		const std::array<uint8_t, 32>& k_enc,
		const std::vector<uint8_t>& iv,
		std::vector<uint8_t>& dst) {

		CipherType alg_mac(k_mac);
		CMAC<CipherType> cmac(alg_mac, CipherType::byte_block_size * 8);
		//CMAC<CipherType> cmac(k_mac, CipherType::byte_block_size * 8);
		CipherType alg_enc(k_enc);
		CTR<CipherType> ctr(alg_enc, iv);
		//CTR<CipherType> ctr(k_enc, iv);

		std::vector<uint8_t> k_keymac = {};
		ctr.decrypt(kexp, k_keymac);

		std::vector<uint8_t> keymac(CipherType::byte_block_size);
		std::copy(k_keymac.begin() + (k_keymac.size() - CipherType::byte_block_size), k_keymac.end(), keymac.begin());
		k_keymac.resize(k_keymac.size() - CipherType::byte_block_size); // k_keymac became k here

		cmac.update(iv);
		cmac.update(k_keymac);
		std::vector<uint8_t> calculated_keymac = {};
		cmac.finalize(calculated_keymac);

		if (calculated_keymac != keymac) {
			throw "MACs does not match.";
		}

		dst.resize(k_keymac.size());
		std::copy(k_keymac.begin(), k_keymac.end(), dst.begin());
	}



#endif // REFERENCEIMPLEMENTATIONS_KEXP15_H