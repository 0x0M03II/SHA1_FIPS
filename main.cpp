#include "src/sha1.h"
#include <string>
#include <iostream>

int main(int argc, char* argv[])
{
    std::string digest;
    std::string msgs[5] = {
        "This is a test of SHA-1.",
        "Kerckhoff’s principle is the foundation on which modern cryptography is built.",
        "SHA-1 is no longer considered a secure hashing algorithm.",
        "SHA-2 or SHA-3 should be used in place of SHA-1.",
        "Never roll your own crypto!"
    };

    SHA1* implementSha1 = new SHA1;

    for (int i = 0; i < 5; ++i) {
        implementSha1->preprocess(msgs[i]);
        digest = implementSha1->finalize();

        std::cout << "Message: " << msgs[i] << std::endl;
        std::cout << "Digest: " << digest << std::endl;
        std::cout << std::endl;
    }

    return 0;
}