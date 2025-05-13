#ifndef CRISPAPP_NETWORKMANAGER_H
#define CRISPAPP_NETWORKMANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <queue>
#include <WinSock2.h>
#include <WS2tcpip.h>

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    // Инициализация сервера
    bool initializeServer(const std::string& port);
    
    // Инициализация клиента
    bool initializeClient(const std::string& serverAddress, const std::string& port);
    
    // Отправка сообщения
    bool sendMessage(const std::vector<uint8_t>& message);
    
    // Получение сообщения
    bool receiveMessage(std::vector<uint8_t>& message);
    
    // Остановка работы
    void shutdown();

private:
    bool isServer;
    bool isRunning;
    SOCKET serverSocket;
    SOCKET clientSocket;
    std::thread receiveThread;
    std::mutex queueMutex;
    std::queue<std::vector<uint8_t>> messageQueue;
    
    // Обработка входящих сообщений
    void handleIncomingMessages();
    
    // Инициализация WinSock
    bool initializeWinSock();
};

#endif // CRISPAPP_NETWORKMANAGER_H 