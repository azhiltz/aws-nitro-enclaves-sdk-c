#include "cpp_wrapper.h"

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
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

std::vector<char> attestation_cpp_wrapper::request_attestation_doc_str(
            std::string& user_data, 
            std::string& user_nounce
            ) {
    std::cout << "LOG: enter " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;            
    std::vector<char> user_data_vec, user_nounce_vec;
    user_data_vec.resize(user_data.size());
    user_nounce_vec.resize(user_nounce.size());
    user_data_vec.assign(user_data.begin(), user_data.end());
    user_nounce_vec.assign(user_nounce.begin(), user_nounce.end());
    
    std::cout << "LOG: begin to get doc " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    
    //std::string r;
    std::vector<char> att_doc;
    if ( !request_attestation_doc(user_data_vec, user_nounce_vec, att_doc) ) {
        
        //.assign(att_doc.begin(), att_doc.end());
        std::cout << "LOG: get doc wrong " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    }
    std::cout << "LOG: get over " << __FUNCTION__ <<" line: " << __LINE__ <<std::endl;
    return att_doc;
}

std::string attestation_cpp_wrapper::decrypt_data_with_private_key_str(std::string& ciphertext) {
    std::vector<char> plaintext_vec, ciphertext_vec;
    plaintext_vec.resize(ciphertext.size());
    plaintext_vec.assign(ciphertext.begin(), ciphertext.end());
    
    std::string r;
    if (decrypt_data_with_private_key(plaintext_vec, ciphertext_vec)) {
        r.assign(ciphertext_vec.begin(), ciphertext_vec.end());
    }
    
    return r;
}