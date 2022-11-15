#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/kms.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    int ret = 0;
    struct aws_allocator *allocator = NULL;
    
    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);
    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);
    
    allocator = aws_nitro_enclaves_get_allocator();
    
    /* generate the rsa key */
    struct aws_rsa_keypair * rsa_key = aws_attestation_rsa_keypair_new( allocator, AWS_RSA_2048);
    
    struct aws_recipient* recipient = aws_recipient_new(allocator);
    
  
    ret = aws_attestation_request(allocator, rsa_key, &recipient->attestation_document);
    if ( ret != AWS_OP_SUCCESS) {
        goto FINI;
    }
    recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;
    /* json output */
    struct aws_string* recepint_json = aws_recipient_to_json(recipient);
    
    do {
        fprintf(stderr, "attestation doc: %s\n", aws_string_c_str(recepint_json));
        sleep(1);
    } while(1);
    
    aws_string_destroy(recepint_json);
    aws_recipient_destroy(recipient);
    
FINI:
    aws_attestation_rsa_keypair_destroy(rsa_key);
    aws_nitro_enclaves_library_clean_up();
    
    return ret;
}
