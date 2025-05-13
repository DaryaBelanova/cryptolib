#ifndef REFERENCEIMPLEMENTATIONS_CRISPSUITE_H
#define REFERENCEIMPLEMENTATIONS_CRISPSUITE_H

#include <array>
#include <vector>
#include <stdint.h>

namespace Crisp {

	// јбстрактный класс, представл€ющий криптографический набор CRISP

	class CrispSuite {

	public:

		virtual ~CrispSuite() = default;

		virtual void encrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) = 0;

		virtual void decrypt(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& dst) = 0;

		virtual void calculate_mac(const std::vector<uint8_t>& crispMsg, std::vector<uint8_t>& dst) = 0;

		virtual bool verify_mac(const std::vector<uint8_t>& crispMsg, const std::vector<uint8_t>& mac) = 0;

		virtual std::vector<uint8_t> get_k_enc() = 0;

		virtual std::vector<uint8_t> get_k_mac() = 0;

		uint8_t get_CS() {
			return CS_;
		}

		virtual bool is_encryption_provided() = 0;

		size_t get_mac_byte_length() {
			return mac_byte_length_;
		}


	protected:

		CrispSuite(uint8_t CS, size_t mac_bit_length) : CS_(CS), mac_byte_length_(mac_bit_length / 8) {}

		uint8_t CS_;

		size_t mac_byte_length_;

		virtual void calculate_iv(const std::vector<uint8_t>& seqNum) = 0;

		virtual std::array<uint8_t, 32> get_k_mac(const std::vector<uint8_t>& seqNum,
			const std::vector<uint8_t>& sourceId) = 0;

		virtual std::array<uint8_t, 32> get_k_enc(const std::vector<uint8_t>& seqNum,
			const std::vector<uint8_t>& sourceId) = 0;
	};

} // namespace Crisp

#endif //REFERENCEIMPLEMENTATIONS_CRISPSUITE_H