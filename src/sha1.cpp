#include "sha1.h"

void SHA1::preprocess(std::string message)
{
    padMessage(message);
    parseMessage(message);
}

void SHA1::padMessage(std::string& message) {
    uint64_t originalBitLength = message.size() * 8;

    // Append bit
    message.push_back(static_cast<char>(0x80));

    // FIPS padding algorithm
    size_t currentLengthInBits = message.size() * 8;
    size_t paddingBits = (448 - (currentLengthInBits % 512)) % 512;
    size_t paddingLength = paddingBits / 8;

    // Append zero bits
    message.append(paddingLength, 0x00);

    // Append the original length in bits as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        message.push_back(static_cast<char>((originalBitLength >> (i * 8)) & 0xff));
    }
}


void SHA1::parseMessage(std::string& message)
{
    // message schedule words
    uint32_t W[80];
    size_t block = 64;
    int T, a, b, c, d, e;

    for (int k = 0; k < message.size(); k += block) {

        uint32_t words[16];

        for (int j = 0; j < 16; ++j) {

            /* place 4-byte words in words container */
            size_t index = k + j * 4;
            words[j] = (static_cast<uint32_t>(static_cast<unsigned char>(message[index])) << 24) |
                       (static_cast<uint32_t>(static_cast<unsigned char>(message[index + 1])) << 16) |
                       (static_cast<uint32_t>(static_cast<unsigned char>(message[index + 2])) << 8) |
                       (static_cast<uint32_t>(static_cast<unsigned char>(message[index + 3])));
        }

        // add first 16 words
        for (int t = 0; t < 16; ++t) {
            W[t] = words[t];
        }

        /* Word Schedule algorithm FIPS.180-4 */
        for (int t = 16; t < 80; ++t) {
            W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
            W[t] = (W[t] << 1) | (W[t] >> 31);
        }

        a = initHash->h0, b = initHash->h1, c = initHash->h2;
        d = initHash->h3, e = initHash->h4;

        /* f(t) = (b, c, d) */
        for (int i = 0; i < 80; ++i) {

            T = ((a << 5) | (a >> (32 - 5))) + e + W[i];

            if (i < 20) {
                T += ((b & c) ^ (~b & ~d)) + constants->a;
            }
            else if (i < 40) {
                T += (b ^ c ^ d) + constants->b;
            }
            else if (i < 60) {
                T += ((b & c) ^ (b & d) ^ (c & d)) + constants->c;
            }
            else {
                T += (b ^ c ^ d) + constants->d;
            }
            
            // swaps
            e = d;
            d = c;
            c = (b << 30) | (b >> (32 - 30));
            b = a;
            a = T;
        }

        // ith intermediate hash
        initHash->h0 += a;
        initHash->h1 += b;
        initHash->h2 += c;
        initHash->h3 += d;
        initHash->h4 += e;
    }
}

std::string SHA1::finalize() const {
    std::stringstream ss;

    // convert to hex
    ss << std::hex << std::setw(8) << std::setfill('0') << initHash->h0
       << std::setw(8) << initHash->h1
       << std::setw(8) << initHash->h2
       << std::setw(8) << initHash->h3
       << std::setw(8) << initHash->h4;

    return ss.str();
}
