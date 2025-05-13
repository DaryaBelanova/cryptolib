#include <memory>
#include <unordered_map>
#include <string>
#include "AppMsgHeader.h"
#include "AppMessage.h"
#include "AppMsgPayload.h"
#include "NewKeyRequest.h"
#include "KeyResponse.h"
#include "../ReferenceImplementations/crisp/CrispMessage.h"

class MsgHandler {

public:

    std::unique_ptr<AppMsgHeader> createHeader(std::unordered_map<std::string, std::vector<uint8_t>>& headerDataMap);

	std::string createMessage(std::unordered_map<std::string, std::vector<uint8_t>>& headerDataMap,
		std::unordered_map<std::string, std::vector<uint8_t>>& payloadDataMap,
		std::unordered_map<std::string, std::vector<uint8_t>>& crispDataMap,
		std::unordered_map<std::string, std::vector<uint8_t>>& targetKeyDataMap);
	
	//void make_crisp(AppMessage<AppMsgPayload> msg, std::unordered_map<std::string, std::vector<uint8_t>> &crispParams, std::unordered_map<std::string, std::vector<uint8_t>>& headerDataMap);

private:

	void fill_header(AppMsgHeader& header, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap);
	void fill_KeyResponse(KeyResponse& payload, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap, std::unordered_map<std::string, std::vector<uint8_t>>& targetKeyDataMap);
	void fill_NewKeyRequest(NewKeyRequest& payload, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap);
};