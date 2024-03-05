#ifndef FIPS_COSC583_SHA1
#define FIPS_COSC583_SHA1
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

/* initial Hash Values SHA1 */
typedef struct sha1InitHash {
    int h0 = 0x67452301;
    int h1 = 0xefcdab89;
    int h2 = 0x98badcfe;
    int h3 = 0x10325476;
    int h4 = 0xc3d2e1f0;

    sha1InitHash() {};
} initHash_t;

typedef struct sha1Constants {
    int a = 0x5a827999;
    int b = 0x6ed9eba1;
    int c = 0x8f1bbcdc;
    int d = 0xca62c1d6;
} constants_t;

class SHA1 {
    public:
        /* preprocess message */
        void preprocess(std::string message);
        
        /* pad message */
        void padMessage(std::string& message);
        
        /* parse message*/
        void parseMessage(std::string& message);

        /* hash message */
        void hashMessage(std::string& message);

        /* finalize hash values */
        std::string finalize() const;

        /* constructor */
        SHA1(){ 
            //memset(words, 0, sizeof(words));
            initHash = new initHash_t;
            constants = new constants_t;
        }

    private:
        uint32_t words[16];
        initHash_t* initHash;
        constants_t* constants;
};

#endif