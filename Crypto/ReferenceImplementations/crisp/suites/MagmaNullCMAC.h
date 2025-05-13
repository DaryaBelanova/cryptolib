#ifndef REFERENCEIMPLEMENTATIONS_MAGMANULLCMAC_H
#define REFERENCEIMPLEMENTATIONS_MAGMANULLCMAC_H

#include "CrispSuite.h"
#include "../../ciphersuite/Magma.h"
#include "../../ciphermodes/CMAC.h"
#include "../../kdf/KDF.h"

using namespace EncryptionAlgorithms;
using namespace CipherModes;

namespace Crisp {

	class MagmaNullCMAC : public Crisp::CrispSuite {

	public:

		MagmaNullCMAC(
			const std::vector<uint8_t>& seqNum,
			const std::array<uint8_t, 32>& baseKey,
			const std::vector<uint8_t>& sourceId);

		void encrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) override;

		void decrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) override;

		void calculate_mac(const std::vector<uint8_t>& crispMsg, std::vector<uint8_t>& dst) override;

		bool verify_mac(const std::vector<uint8_t>& crispMsg, const std::vector<uint8_t>& mac) override;

		bool is_encryption_provided() override;

		std::vector<uint8_t> get_k_enc() override;

		std::vector<uint8_t> get_k_mac() override;


	private:

		KDF<CMAC<Magma>> kdf_;

		std::array<uint8_t, 32> k_mac_;

		std::vector<uint8_t> iv_;

		Magma mac_alg_;
		CMAC<Magma> mac_mode_;

		std::array<uint8_t, 32> get_k_enc(const std::vector<uint8_t>& seqNum,
			const std::vector<uint8_t>& sourceId) override;

		std::array<uint8_t, 32> get_k_mac(const std::vector<uint8_t>& seqNum,
			const std::vector<uint8_t>& sourceId) override;


		void calculate_iv(const std::vector<uint8_t>& seqNum) override;
	};

} // namespace Crisp

#endif //REFERENCEIMPLEMENTATIONS_MAGMANULLCMAC_H