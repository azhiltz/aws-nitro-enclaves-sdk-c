project(attestation_sdk_python CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")
include_directories(/usr/include/python3.7m)

#add_subdirectory(../pybind11)

#find_package(Python COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

set(KMSTOOL_ENCLAVE_PROJECT_NAME pyattestation)
pybind11_add_module(pyattestation cpp_wrapper.cpp function_wrapper.cpp)

#add_executable(${KMSTOOL_ENCLAVE_PROJECT_NAME} "cpp_wrapper.cpp")
#add_library(${KMSTOOL_ENCLAVE_PROJECT_NAME} SHARED cpp_wrapper.cpp function_wrapper.cpp)



#aws_set_common_properties(${KMSTOOL_ENCLAVE_PROJECT_NAME})

include_directories(${KMSTOOL_ENCLAVE_PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

target_link_libraries(${KMSTOOL_ENCLAVE_PROJECT_NAME} PUBLIC aws-nitro-enclaves-sdk-c pybind11::module)


#target_link_libraries(pyattestation aws-nitro-enclaves-sdk-c)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " kmstool will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${KMSTOOL_ENCLAVE_PROJECT_NAME}
    EXPORT ${KMSTOOL_ENCLAVE_PROJECT_NAME}-targets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        COMPONENT library)
