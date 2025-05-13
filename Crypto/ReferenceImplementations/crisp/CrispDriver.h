#ifndef REFERENCEIMPLEMENTATIONS_CRISPDRIVER_H
#define REFERENCEIMPLEMENTATIONS_CRISPDRIVER_H

#include <vector>
#include <map>
#include <memory>
#include "suites/CrispSuite.h"
#include "CrispMessage.h"

namespace Crisp {

	class CrispDriver {

	public:

		CrispDriver();

		~CrispDriver();

		void send(const std::vector<uint8_t>& payloadData, std::vector<uint8_t>& crispMsg);

		void send(const std::vector<uint8_t>& payloadData, CrispMessage& crispMsg);

		void receive(const std::vector<uint8_t>& baseKey, const std::vector<uint8_t>& sourceId, int size, const std::vector<uint8_t>& crispData, std::vector<uint8_t>& payloadData);

		void configure_suite(uint8_t CS,
			const std::vector<uint8_t>& seqNum,
			const std::array<uint8_t, 32>& baseKey,
			const std::vector<uint8_t>& sourceId);

		void configure_state_with_suite(uint8_t externalKeyIdFlag,
			const std::vector<uint8_t>& baseKey,
			const std::vector<uint8_t>& keyId,
			const std::vector<uint8_t>& sourceId,
			uint16_t size,
			const std::vector<uint8_t>& seqNum,
			uint8_t CS,
			std::vector<uint8_t> version = { 0x00, 0x00 });


		void configure_state(uint8_t externalKeyIdFlag,
			const std::vector<uint8_t>& keyId,
			uint16_t size,
			const std::vector<uint8_t>& seqNum,
			uint8_t CS,
			std::vector<uint8_t> version = { 0x00, 0x00 });

	private:

		std::unique_ptr<CrispSuite> suite_;

		uint8_t ExternalKeyIdFlag_;

		std::vector<uint8_t> KeyId_;

		uint16_t Size_;

		std::map<uint64_t, bool> accepted_messages_range_;

		std::vector<uint8_t> SeqNum_; // 6 bytes

		std::vector<uint8_t> Version_; // big endian (2 bytes)

		uint8_t CS_;

		void increment_SeqNum();

		uint64_t SeqNum_to_uint64_t(const std::vector<uint8_t>& seqNumVec);
	};

} // namespace Crisp

#endif //REFERENCEIMPLEMENTATIONS_CRISPDRIVER_H