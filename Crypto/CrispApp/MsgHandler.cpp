#include "MsgHandler.h"
#include "DataReader.h"
#include "AppMsgHeader.h"
#include <iostream>
#include <string>

void MsgHandler::fill_header(AppMsgHeader& header, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap) {
	header.set_Ver(dataMap.at("version"));
	header.set_SenderID(dataMap.at("senderId"));
	header.set_RecipientId(dataMap.at("recipientId"));
	header.set_SessionId(dataMap.at("sessionId"));
	header.set_MsgType(dataMap.at("messageType"));
	//header.set_HeaderFlags({ dataMap.at("flags.headerType")[0] , dataMap.at("flags.messageType")[0] });
	uint8_t flags = (dataMap.at("flags.headerType")[0] << 1) | (dataMap.at("flags.messageType")[0]);
	header.set_HeaderFlags({flags });
	header.set_TimeStamp(dataMap.at("timeStamp"));
}

void MsgHandler::fill_KeyResponse(KeyResponse& payload, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap, std::unordered_map<std::string, std::vector<uint8_t>>& targetKeyDataMap) {
	payload.set_PairConId(dataMap.at("pairConnId"));
	//payload.set_Flags({ dataMap.at("flags.keyCreationType")[0] , dataMap.at("flags.keyDeliveryAckRequired")[0], dataMap.at("flags.hasAdditionalData")[0] });
	uint8_t flags = (dataMap.at("flags.keyCreationType")[0]) | (dataMap.at("flags.keyDeliveryAckRequired")[0] << 1) | (dataMap.at("flags.hasAdditionalData")[0] << 2);
	payload.set_Flags({flags});
	payload.set_TargetKeyId(dataMap.at("targetKeyId"));
	payload.set_CS_KW(dataMap.at("csKw"));
	payload.set_KeySize(dataMap.at("keySize"));
	if (dataMap.count("keyLabel") > 0) {
		payload.set_KeyLabelSize(dataMap.at("keyLabelSize"));
		payload.set_KeyLabel(dataMap.at("keyLabel"));
	}
	payload.make_KeyContainer_exp(dataMap.at("csKw"), 
		targetKeyDataMap.at("targetKey"), 
		targetKeyDataMap.at("keyMacCont"), 
		targetKeyDataMap.at("keyEncCont"), 
		targetKeyDataMap.at("keyWrapId"), 
		targetKeyDataMap.at("iv"));
}

void MsgHandler::fill_NewKeyRequest(NewKeyRequest& payload, std::unordered_map<std::string, std::vector<uint8_t>>& dataMap) {
	payload.set_PairConId(dataMap.at("pairConnId"));
	//payload.set_Flags({ dataMap.at("flags.hasKeyId")[0] ,  dataMap.at("flags.hasAdditionalData")[0] });
	uint8_t flag = (dataMap.at("flags.hasKeyId")[0] << 1) | dataMap.at("flags.hasAdditionalData")[0];
	payload.set_Flags({ flag });
	payload.set_Timer(dataMap.at("timer"));
	payload.set_KeySize(dataMap.at("keySize"));
	payload.set_CS_KW(dataMap.at("csKw"));
	if (dataMap.count("keyLabel") > 0) {
		payload.set_KeyLabelSize(dataMap.at("keyLabelSize"));
		payload.set_KeyLabel(dataMap.at("keyLabel"));
	}
}

std::unique_ptr<AppMsgHeader> MsgHandler::createHeader(std::unordered_map<std::string, std::vector<uint8_t>>& dataMap) {
	AppMsgHeader header;
	fill_header(header, dataMap);
	return std::make_unique<AppMsgHeader>(header);
}

std::string MsgHandler::createMessage(std::unordered_map<std::string, std::vector<uint8_t>>& headerDataMap,
                                      std::unordered_map<std::string, std::vector<uint8_t>>& payloadDataMap,
                                      std::unordered_map<std::string, std::vector<uint8_t>>& crispDataMap,
                                      std::unordered_map<std::string, std::vector<uint8_t>>& targetKeyDataMap) {

	uint8_t messageType = headerDataMap.at("messageType")[0];
	uint8_t flags_headerType = headerDataMap.at("flags.headerType")[0];
	uint8_t flags_messageType = headerDataMap.at("flags.messageType")[0];

		switch (messageType) {
		case 2: {
			if (flags_headerType == 0) { // если запрос
				NewKeyRequest payload;
				fill_NewKeyRequest(payload, payloadDataMap);
				AppMessage<NewKeyRequest> msg(*createHeader(headerDataMap), payload);
				Crisp::CrispMessage crisp;
				msg.make_crisp(crisp, crispDataMap.at("externalKeyIdFlag")[0], crispDataMap.at("keyValue"), crispDataMap.at("keyId"), headerDataMap.at("senderId"), 256, crispDataMap.at("seqNum"), crispDataMap.at("cs")[0], headerDataMap.at("version"));
				return crisp.to_string();
			}
			else { // если ответ
				if (flags_messageType == 0) { // если не ошибка 
					KeyResponse payload;
					fill_KeyResponse(payload, payloadDataMap, targetKeyDataMap);
					AppMessage<KeyResponse> msg(*createHeader(headerDataMap), payload);
					Crisp::CrispMessage crisp;
					msg.make_crisp(crisp, crispDataMap.at("externalKeyIdFlag")[0], crispDataMap.at("keyValue"), crispDataMap.at("keyId"), headerDataMap.at("senderId"), 256, crispDataMap.at("seqNum"), crispDataMap.at("cs")[0], headerDataMap.at("version"));
					return crisp.to_string();
				}
			}
			break;
		}

		default:
			break;
		}
}