set(test_program test_key)

list(APPEND DEPS_LIBS ${PROJECT_NAME} gtest)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test)

message(STATUS "TEST-DEPS_LIBS:${DEPS_LIBS}")

file(GLOB_RECURSE TEST_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${test_program} ${TEST_SRCS})
target_link_libraries(${test_program} PUBLIC ${DEPS_LIBS})