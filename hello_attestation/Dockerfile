from enclave_sdk_base:latest

COPY ./hello_attestation.py /app/
COPY ./extract_attestation.py /app/
COPY ./run.sh /app/
RUN chmod +x /app/run.sh
#RUN python3 -m pip install base64 --user
RUN python3 -m pip install cbor2 cryptography --user
CMD ["app/run.sh"]