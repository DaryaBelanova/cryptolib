
#include <memory>
#include "CrispSuiteFactory.h"
#include "suites/MagmaCTRCMAC.h"
#include "suites/MagmaNullCMAC.h"
#include "suites/MagmaCTRCMAC8.h"
#include "suites/MagmaNullCMAC8.h"

namespace Crisp {

	std::unique_ptr<CrispSuite> CrispSuiteFactory::create_suite(uint8_t CS,
		const std::vector<uint8_t>& seqNum,
		const std::array<uint8_t, 32>& baseKey,
		const std::vector<uint8_t>& sourceId) {

		switch (CS) {
		case 0x01:
			return std::make_unique<MagmaCTRCMAC>(seqNum, baseKey, sourceId);

		case 0x02:
			return std::make_unique<MagmaNullCMAC>(seqNum, baseKey, sourceId);

		case 0x03:
			return std::make_unique<MagmaCTRCMAC8>(seqNum, baseKey, sourceId);

		case 0x04:
			return std::make_unique<MagmaNullCMAC8>(seqNum, baseKey, sourceId);

		default:
			throw "Invalid CS.";
		}

	}
} // namespace Crisp