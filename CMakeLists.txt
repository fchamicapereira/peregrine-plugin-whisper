# CMake basics
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(Whisper)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add path_prefix and options for PyTorch C++
set(CMAKE_PREFIX_PATH /opt/pytorch)
find_package(Torch REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TORCH_CXX_FLAGS}")

# Add sub-directories
add_subdirectory(commune)

# Add the target sorce code files
aux_source_directory(. DIR_SRCS)
add_executable(${PROJECT_NAME} "${DIR_SRCS}")

# Add library dependencies
target_link_libraries(${PROJECT_NAME} gflags)
target_link_libraries(${PROJECT_NAME} commune)
