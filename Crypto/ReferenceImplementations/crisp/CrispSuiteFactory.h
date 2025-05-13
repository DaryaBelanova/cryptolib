#ifndef REFERENCEIMPLEMENTATIONS_CRISPSUITEFACTORY_H
#define REFERENCEIMPLEMENTATIONS_CRISPSUITEFACTORY_H

#include <vector>
#include <array>
#include "suites/CrispSuite.h"

namespace Crisp {

	class CrispSuiteFactory {

	public:

		static std::unique_ptr<CrispSuite> create_suite(uint8_t CS,
			const std::vector<uint8_t>& seqNum,
			const std::array<uint8_t, 32>& baseKey,
			const std::vector<uint8_t>& sourceId);

	private:

		CrispSuiteFactory() {}
	};

} // namespace Crisp

#endif //REFERENCEIMPLEMENTATIONS_CRISPSUITEFACTORY_H