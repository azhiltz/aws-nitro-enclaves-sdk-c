/*
 * pybind of attestation function
 */
 
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <iostream>

#include "cpp_wrapper.h"
namespace py = pybind11;


PYBIND11_MODULE( pyattestation, m ){
    m.doc() = "pybind11 attestation";
    pybind11::class_<attestation_cpp_wrapper>(m, "attestation" )
        .def( pybind11::init() )
        .def( "init_key_pair", &attestation_cpp_wrapper::init_key_pair )
        .def( "request_attestation_doc", &attestation_cpp_wrapper::request_attestation_doc_str )
        .def("request_attestation_default_doc", &attestation_cpp_wrapper::request_attestation_default_doc)
        .def( "decrypt_data_with_private_key", &attestation_cpp_wrapper::decrypt_data_with_private_key_str );
}