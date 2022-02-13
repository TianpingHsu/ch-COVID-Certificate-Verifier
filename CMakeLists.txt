cmake_minimum_required(VERSION 3.10.2)
project(ch
	DESCRIPTION "swiss hcert decoder and verifier"
	VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include_directories(./include)
link_directories(./third_party)

add_executable (ch ./src/ch.cpp ./src/base64.cpp ./src/test_ch.cpp)
target_link_libraries(ch libbase45.a libz.a libssl.a libcrypto.a libqcbor.a t_cose pthread m dl)

