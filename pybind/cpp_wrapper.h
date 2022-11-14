#ifndef PY_BIND_CPP_WRAPPER_H
#define PY_BIND_CPP_WRAPPER_H

#include <cstdint>
#include <vector>

class attestation_cpp_wrapper {
        
    public:    
        attestation_cpp_wrapper();
        
        ~attestation_cpp_wrapper();
        
        bool init_key_pair();
        
        bool request_attestation_doc(
            std::vector<uint8_t>& user_data, 
            std::vector<uint8_t>& user_nounce, 
            std::vector<uint8_t>& attestation_doc);
        
        bool decrypt_data_with_private_key(
            std::vector<uint8_t>& ciphertext, 
            std::vector<uint8_t>& plaintext);
        
    private:
        /* pointer to  key_pair */
        uintptr_t key_pair_;
        /* pointer to 2 allocator */
        uintptr_t allocator_;
};

#endif //PY_BIND_CPP_WRAPPER_H