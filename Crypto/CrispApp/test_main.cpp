#include <iostream>
#include <string>
#include "MsgHandler.h"
#include "DataReader.h"
#include "AppMessage.h"
#include "NetworkManager.h"

void printUsage() {
	std::cout << "Usage:" << std::endl;
	std::cout << "Server mode: CrispApp.exe -s <port> <config_file>" << std::endl;
	std::cout << "Client mode: CrispApp.exe -c <server_address> <port> <config_file>" << std::endl;
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		printUsage();
		return 1;
	}

	std::string mode = argv[1];
	NetworkManager networkManager;
	
	if (mode == "-s") {
		// Серверный режим
		if (argc != 4) {
			printUsage();
			return 1;
		}
		
		std::string port = argv[2];
		std::string configFile = argv[3];
		
		if (!networkManager.initializeServer(port)) {
			std::cerr << "Failed to initialize server" << std::endl;
			return 1;
		}
		
		std::cout << "Server started on port " << port << std::endl;
	}
	else if (mode == "-c") {
		// Клиентский режим
		if (argc != 5) {
			printUsage();
			return 1;
		}
		
		std::string serverAddress = argv[2];
		std::string port = argv[3];
		std::string configFile = argv[4];
		
		if (!networkManager.initializeClient(serverAddress, port)) {
			std::cerr << "Failed to connect to server" << std::endl;
			return 1;
		}
		
		std::cout << "Connected to server " << serverAddress << ":" << port << std::endl;
	}
	else {
		printUsage();
		return 1;
	}

	// Читаем конфигурацию
	DataReader reader;
	reader.readFromFile(argv[argc-1]);

	MsgHandler handler;
	
	// Основной цикл обработки сообщений
	while (true) {
		// Создаем сообщение из конфигурации
		std::string msg = handler.createMessage(reader.headerDataMap, 
											  reader.payloadDataMap, 
											  reader.crispDataMap, 
											  reader.targetKeyDataMap);
		
		// Получаем байты сообщения
		std::vector<uint8_t> messageBytes(msg.begin(), msg.end());
		
		// Отправляем сообщение
		if (!networkManager.sendMessage(messageBytes)) {
			std::cerr << "Failed to send message" << std::endl;
			break;
		}
		
		// Получаем ответное сообщение
		std::vector<uint8_t> receivedBytes;
		if (networkManager.receiveMessage(receivedBytes)) {
			std::string receivedMsg(receivedBytes.begin(), receivedBytes.end());
			std::cout << "Received message: " << receivedMsg << std::endl;
		}
		
		// Небольшая задержка между сообщениями
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}