#include "NetworkManager.h"
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

NetworkManager::NetworkManager() : 
    isServer(false), 
    isRunning(false),
    serverSocket(INVALID_SOCKET),
    clientSocket(INVALID_SOCKET) {
}

NetworkManager::~NetworkManager() {
    shutdown();
}

bool NetworkManager::initializeWinSock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return false;
    }
    return true;
}

bool NetworkManager::initializeServer(const std::string& port) {
    if (!initializeWinSock()) {
        return false;
    }

    struct addrinfo *result = nullptr, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the local address and port to be used by the server
    int iResult = getaddrinfo(NULL, port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return false;
    }

    serverSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return false;
    }

    // Setup the TCP listening socket
    iResult = bind(serverSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    freeaddrinfo(result);

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    isServer = true;
    isRunning = true;
    
    // Запуск потока для обработки входящих сообщений
    receiveThread = std::thread(&NetworkManager::handleIncomingMessages, this);
    
    return true;
}

bool NetworkManager::initializeClient(const std::string& serverAddress, const std::string& port) {
    if (!initializeWinSock()) {
        return false;
    }

    struct addrinfo *result = nullptr, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    int iResult = getaddrinfo(serverAddress.c_str(), port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return false;
    }

    clientSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return false;
    }

    // Connect to server
    iResult = connect(clientSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "Unable to connect to server!" << std::endl;
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        freeaddrinfo(result);
        WSACleanup();
        return false;
    }

    freeaddrinfo(result);

    isServer = false;
    isRunning = true;
    
    // Запуск потока для обработки входящих сообщений
    receiveThread = std::thread(&NetworkManager::handleIncomingMessages, this);
    
    return true;
}

bool NetworkManager::sendMessage(const std::vector<uint8_t>& message) {
    if (!isRunning) {
        return false;
    }

    SOCKET sendSocket = isServer ? clientSocket : clientSocket;
    
    // Сначала отправляем размер сообщения
    uint32_t messageSize = static_cast<uint32_t>(message.size());
    int iResult = send(sendSocket, reinterpret_cast<char*>(&messageSize), sizeof(messageSize), 0);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "send failed: " << WSAGetLastError() << std::endl;
        return false;
    }

    // Затем отправляем само сообщение
    iResult = send(sendSocket, reinterpret_cast<const char*>(message.data()), messageSize, 0);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "send failed: " << WSAGetLastError() << std::endl;
        return false;
    }

    return true;
}

bool NetworkManager::receiveMessage(std::vector<uint8_t>& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    if (messageQueue.empty()) {
        return false;
    }
    
    message = std::move(messageQueue.front());
    messageQueue.pop();
    return true;
}

void NetworkManager::handleIncomingMessages() {
    SOCKET receiveSocket = isServer ? clientSocket : clientSocket;
    
    while (isRunning) {
        // Получаем размер сообщения
        uint32_t messageSize;
        int iResult = recv(receiveSocket, reinterpret_cast<char*>(&messageSize), sizeof(messageSize), 0);
        if (iResult <= 0) {
            break;
        }

        // Получаем само сообщение
        std::vector<uint8_t> message(messageSize);
        iResult = recv(receiveSocket, reinterpret_cast<char*>(message.data()), messageSize, 0);
        if (iResult <= 0) {
            break;
        }

        // Добавляем сообщение в очередь
        std::lock_guard<std::mutex> lock(queueMutex);
        messageQueue.push(std::move(message));
    }
}

void NetworkManager::shutdown() {
    isRunning = false;
    
    if (receiveThread.joinable()) {
        receiveThread.join();
    }
    
    if (serverSocket != INVALID_SOCKET) {
        closesocket(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
    
    WSACleanup();
} 