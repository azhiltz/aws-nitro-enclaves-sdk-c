#ifndef PY_BIND_CPP_WRAPPER_H
#define PY_BIND_CPP_WRAPPER_H

#include <cstdint>
#include <vector>
#include <string>

class attestation_cpp_wrapper {
        
    public:    
        attestation_cpp_wrapper();
        
        ~attestation_cpp_wrapper();
        
        bool init_key_pair();
        
        bool request_attestation_doc(
            std::vector<char>& user_data, 
            std::vector<char>& user_nounce, 
            std::vector<char>& attestation_doc);
            
        std::vector<char> request_attestation_doc_str(
            std::string& user_data, 
            std::string& user_nounce
            );
        
        std::string request_attestation_default_doc();
        
        bool decrypt_data_with_private_key(
            std::vector<char>& ciphertext, 
            std::vector<char>& plaintext);
        
        std::string decrypt_data_with_private_key_str(std::string& ciphertext);
        
    private:
        /* pointer to  key_pair */
        uintptr_t key_pair_;
        /* pointer to 2 allocator */
        uintptr_t allocator_;
};

#endif //PY_BIND_CPP_WRAPPER_H