#include "cpp_wrapper.h"

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/common/encoding.h>
#include <iostream>

attestation_cpp_wrapper::attestation_cpp_wrapper() {
    key_pair_ = (uintptr_t)nullptr;
    allocator_ = (uintptr_t)nullptr;
    
    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);
    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);
}

attestation_cpp_wrapper::~attestation_cpp_wrapper() {
    if (key_pair_ != (uintptr_t)nullptr) {
        aws_attestation_rsa_keypair_destroy((struct aws_rsa_keypair*)key_pair_);
    }
    
    aws_nitro_enclaves_library_clean_up();
}

bool attestation_cpp_wrapper::init_key_pair() {
    if (key_pair_ != (uintptr_t)nullptr) {
        aws_attestation_rsa_keypair_destroy((struct aws_rsa_keypair*)key_pair_);
    }
    if (allocator_ == (uintptr_t)nullptr) {
        struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
        allocator_ = (uintptr_t)(allocator);
    }
    
    struct aws_rsa_keypair* key_pair_c = aws_attestation_rsa_keypair_new( (struct aws_allocator*)(allocator_), AWS_RSA_2048 );
    if (key_pair_c==NULL) {
        return false;
    }
    
    key_pair_ = (uintptr_t)(key_pair_c);
    return true;
}

static void copy_aws_buffer_2_vector(struct aws_byte_buf* aws_buffer, std::vector<char>& dst) {
    dst.insert(dst.end(), aws_buffer->buffer, aws_buffer->buffer+aws_buffer->len);
}

bool attestation_cpp_wrapper::request_attestation_doc(
    std::vector<char>& user_data, 
    std::vector<char>& user_nounce, 
    std::vector<char>& attestation_doc) {
    //not init
    if (key_pair_ == (uintptr_t)nullptr) {
        return false;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_byte_buf byte_buf;
    
    int ret = aws_attestation_request_with_user_data_nounce(
        allocator, key_pair, 
        (uint8_t*)&user_data[0], user_data.size(), 
        (uint8_t*)&user_nounce[0], user_data.size(), 
        &byte_buf );
    
    if(ret != AWS_OP_SUCCESS) {
        if (aws_byte_buf_is_valid(&byte_buf)) {
            aws_byte_buf_clean_up_secure(&byte_buf);
        }
        return false;
    }
    
    //copy data from buffer
    copy_aws_buffer_2_vector(&byte_buf, attestation_doc);
    
    if (aws_byte_buf_is_valid(&byte_buf)) {
        aws_byte_buf_clean_up_secure(&byte_buf);
    }
    
    return true;
}

bool attestation_cpp_wrapper::decrypt_data_with_private_key(
    std::vector<char>& ciphertext, 
    std::vector<char>& plaintext) {
    
    //not init
    if (key_pair_ == (uintptr_t)nullptr) {
        return false;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_byte_buf plain_buf, cipher_buf;
    
    //memcpy cipher
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(&ciphertext[0], ciphertext.size());
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(&cipher_buf, allocator, cursor)) {
        return false;
    }
    
    int ret = aws_attestation_rsa_decrypt( allocator, key_pair, &cipher_buf, &plain_buf);
    if (ret != AWS_OP_SUCCESS) {
        goto FINI;
    }
    copy_aws_buffer_2_vector(&plain_buf, plaintext);
    
FINI:
    if (aws_byte_buf_is_valid(&cipher_buf)) {
        aws_byte_buf_clean_up_secure(&cipher_buf);
    }
    if (aws_byte_buf_is_valid(&plain_buf)) {
        aws_byte_buf_clean_up_secure(&plain_buf);
    }
    
    return ret == AWS_OP_SUCCESS;
}

std::string attestation_cpp_wrapper::request_attestation_default_doc() {
    //not init
    std::cout << "LOG: enter " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl; 
    std::string r;
    if (key_pair_ == (uintptr_t)nullptr) {
        return r;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_recipient* recipient = aws_recipient_new(allocator);
    
    std::cout << "LOG: begin to get doc " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    int ret = aws_attestation_request(
        allocator, key_pair, 
        &recipient->attestation_document );
    
    
    std::cout << "LOG: get over " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    if(ret != AWS_OP_SUCCESS) {
        aws_recipient_destroy(recipient);
        return r;
    }
    /* json output */
    struct aws_string* recepint_json = aws_recipient_to_json(recipient);
    
    std::cout << "LOG: begin to assin result " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    //copy data from buffer
    r.assign(recepint_json->bytes, recepint_json->bytes + recepint_json->len);
    
    aws_string_destroy(recepint_json);
    aws_recipient_destroy(recipient);
    
    return r;
}

std::string attestation_cpp_wrapper::request_attestation_doc_str(
            std::string& user_data, 
            std::string& user_nounce
            ) {
    //not init
    std::cout << "LOG: enter " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl; 
    std::string r;
    if (key_pair_ == (uintptr_t)nullptr) {
        return r;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_recipient* recipient = aws_recipient_new(allocator);
    
    std::cout << "LOG: begin to get doc " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    int ret = aws_attestation_request_with_user_data_nounce(
        allocator, key_pair, 
        (uint8_t*)&user_data[0], user_data.size(), 
        (uint8_t*)&user_nounce[0], user_data.size(), 
        &recipient->attestation_document );
    
    std::cout << "LOG: get over " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    if(ret != AWS_OP_SUCCESS) {
        aws_recipient_destroy(recipient);
        return r;
    }
    /* json output */
    struct aws_string* recepint_json = aws_recipient_to_json(recipient);
    
    std::cout << "LOG: begin to assin result " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    //copy data from buffer
    r.assign(recepint_json->bytes, recepint_json->bytes + recepint_json->len);
    
    aws_string_destroy(recepint_json);
    aws_recipient_destroy(recipient);
    
    return r;
}

std::string attestation_cpp_wrapper::decrypt_data_with_private_key_str(std::string& ciphertext) {
     //not init
    std::string r;
    if (key_pair_ == (uintptr_t)nullptr) {
        return r;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_byte_buf plain_buf, cipher_buf, plain_buf_b64;
    aws_byte_buf_init(&cipher_buf, allocator, ciphertext.size());
    aws_byte_buf_init(&plain_buf, allocator, ciphertext.size());
    aws_byte_buf_init(&plain_buf_b64, allocator, ciphertext.size());
    
    //memcpy cipher
    std::cout << "LOG: begin to base64 decode " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(ciphertext.c_str(), ciphertext.size()); //, ciphertext.length());
    aws_base64_decode(&cursor, &cipher_buf);
    
    std::cout << "LOG: begin to decrypt " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    std::cout <<" LOG: cipher is " << cipher_buf.len <<" " << __FUNCTION__ <<" line: " << __LINE__ << std::endl; 
    int ret = aws_attestation_rsa_decrypt( allocator, key_pair, &cipher_buf, &plain_buf);
    if (ret != AWS_OP_SUCCESS) {
        goto FINI;
    }
    
    std::cout << "LOG: begin to base64 encode " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    cursor = aws_byte_cursor_from_buf(&plain_buf);
    aws_base64_encode(&cursor, &plain_buf_b64);
    
    //copy_aws_buffer_2_vector(&cipher_buf_b64, plaintext);
    std::cout << "LOG: assign result " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    r.assign(plain_buf_b64.buffer, plain_buf_b64.buffer+plain_buf_b64.len);
    
FINI:
    if (aws_byte_buf_is_valid(&cipher_buf)) {
        aws_byte_buf_clean_up_secure(&cipher_buf);
    }
    if (aws_byte_buf_is_valid(&plain_buf)) {
        aws_byte_buf_clean_up_secure(&plain_buf);
    }
     if (aws_byte_buf_is_valid(&plain_buf_b64)) {
        aws_byte_buf_clean_up_secure(&plain_buf_b64);
    }
    
    
    return r;
}

std::string attestation_cpp_wrapper::get_public_key() {
    std::string r;
    if (key_pair_ == (uintptr_t)nullptr) {
        return r;
    }
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    
    struct aws_byte_buf buffer_b64;
    aws_byte_buf_init(&buffer_b64, allocator, 4096*2);
    
    aws_attestation_rsa_get_public_key(key_pair, &buffer_b64);
    
    r.assign(buffer_b64.buffer, buffer_b64.buffer + buffer_b64.len);
    
    if(aws_byte_buf_is_valid(&buffer_b64)) {
        aws_byte_buf_clean_up_secure(&buffer_b64);
    }

    return r;
}

std::string attestation_cpp_wrapper::get_private_key() {
     std::string r;
    if (key_pair_ == (uintptr_t)nullptr) {
        return r;
    }
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    
    struct aws_byte_buf buffer_b64;
    aws_byte_buf_init(&buffer_b64, allocator, 4096*2);
    
    aws_attestation_rsa_get_private_key(key_pair, &buffer_b64);
    
    r.assign(buffer_b64.buffer, buffer_b64.buffer + buffer_b64.len);
    
    if(aws_byte_buf_is_valid(&buffer_b64)) {
        aws_byte_buf_clean_up_secure(&buffer_b64);
    }

    return r;
}