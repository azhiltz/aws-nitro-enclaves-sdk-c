#!/bin/bash
echo "begin to build sdk"
cd aws-nitro-enclaves-sdk-c 
docker build -t enclave_sdk_base -f containers/Dockerfile.demo .
echo "begin to build hello demo image"
cd ../hello_attestation
docker build -t hello_demo .
echo "begin to generate eif"
cd ..
nitro-cli build-enclave --docker-uri hello_demo:latest --output-file hello_demo.eif --private-key ./cert/server.key --signing-certificate ./cert/server.crt
echo "begin to run enclave"
nitro-cli terminate-enclave --all
nitro-cli run-enclave --cpu-count 2 --memory 4096 --enclave-cid 32 --eif-path hello_demo.eif --debug-mode 