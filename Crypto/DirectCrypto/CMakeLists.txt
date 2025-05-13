cmake_minimum_required(VERSION 3.8)

add_executable(direct_crypto 
    "direct_crypto.cpp"
)

target_link_libraries(direct_crypto
    PRIVATE
    ReferenceImplementations
)

set_target_properties(direct_crypto PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
) 