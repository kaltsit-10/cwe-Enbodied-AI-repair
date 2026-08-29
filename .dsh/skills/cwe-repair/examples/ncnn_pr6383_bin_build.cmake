cmake_minimum_required(VERSION 3.15)
project(ncnn_pr6383_bin_harness LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(NCNN_SOURCE_DIR "" CACHE PATH "Pinned NCNN source directory")
set(NCNN_BUILD_DIR "" CACHE PATH "Pinned NCNN build directory")
if(NOT NCNN_SOURCE_DIR OR NOT NCNN_BUILD_DIR)
  message(FATAL_ERROR "NCNN_SOURCE_DIR and NCNN_BUILD_DIR are required")
endif()
add_executable(pr6383_bin_error_path
  "${CMAKE_CURRENT_LIST_DIR}/ncnn_pr6383_bin_error_path.cpp")
target_include_directories(pr6383_bin_error_path PRIVATE
  "${NCNN_SOURCE_DIR}/src"
  "${NCNN_BUILD_DIR}/src")
target_link_directories(pr6383_bin_error_path PRIVATE "${NCNN_BUILD_DIR}/src")
target_link_libraries(pr6383_bin_error_path PRIVATE ncnn)
set_target_properties(pr6383_bin_error_path PROPERTIES
  BUILD_RPATH "${NCNN_BUILD_DIR}/src")
