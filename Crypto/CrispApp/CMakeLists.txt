cmake_minimum_required (VERSION 3.8)
project("CrispApp")

set(CMAKE_CXX_STANDARD 17)

add_executable(CrispApp
        "test_main.cpp"
        "DataReader.h"
        "MsgHandler.h"
        "MsgHandler.cpp"
        "DataReader.cpp"
        "AppMessage.h"
        "AppMsgHeader.h"
        "AppMsgPayload.h"
        "KeyResponse.h"
        "NewKeyRequest.h"
        "NetworkManager.h"
        "NetworkManager.cpp")

target_link_libraries(CrispApp PRIVATE 
    ReferenceImplementations
    ws2_32  # Windows Sockets 2
)
