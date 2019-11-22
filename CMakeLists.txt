cmake_minimum_required(VERSION 3.0)

project(sdp-transform C)

set(SDP_LIBRARY_SRC
  sdp_parser.c
  sdp_transform.c)

add_library(${PROJECT_NAME} STATIC ${SDP_LIBRARY_SRC})

set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 11)
set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/deps/cbor)

if(SDP_BUILD_TESTS)
  add_subdirectory(${CMAKE_SOURCE_DIR}/deps/cbor)
  add_executable(sdptest main.c)
  target_link_libraries(sdptest ${PROJECT_NAME} cbor)
endif()
