#!/bin/bash

for((var=0; var < 10; var++))
do
    echo "hello enclave! $var"
    sleep 1
done


ldconfig /app
echo "begin to test attestation demo"
#/app/attestation_demo
echo "begin to test python demo"
python3 /app/hello_attestation.py