#include "cpp_wrapper.h"

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

attestation_cpp_wrapper::attestation_cpp_wrapper() {
    key_pair_ = (uintptr_t)nullptr;
    allocator_ = (uintptr_t)nullptr;
    
    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);
    /* Initialize the entropy pool: this is relevant for TLS */
    //AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);
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

static void copy_aws_buffer_2_vector(struct aws_byte_buf* aws_buffer, std::vector<uint8_t>& dst) {
    dst.insert(dst.end(), aws_buffer->buffer, aws_buffer->buffer+aws_buffer->len);
}

bool attestation_cpp_wrapper::request_attestation_doc(
    std::vector<uint8_t>& user_data, 
    std::vector<uint8_t>& user_nounce, 
    std::vector<uint8_t>& attestation_doc) {
    //not init
    if (key_pair_ == (uintptr_t)nullptr) {
        return false;
    }
    
    struct aws_allocator* allocator = (struct aws_allocator*)(allocator_);
    struct aws_rsa_keypair* key_pair = (struct aws_rsa_keypair*)(key_pair_);
    
    struct aws_byte_buf byte_buf;
    
    int ret = aws_attestation_request_with_user_data_nounce(
        allocator, key_pair, 
        &user_data[0], user_data.size(), 
        &user_nounce[0], user_data.size(), 
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
    std::vector<uint8_t>& ciphertext, 
    std::vector<uint8_t>& plaintext) {
    
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