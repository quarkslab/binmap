//
//   Copyright 2014 QuarksLab
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

#include "binmap/hash.hpp"
#include "binmap/log.hpp"

#ifdef _WIN32
# include <Windows.h>
# include <wincrypt.h>
#else
# include <openssl/sha.h>
#endif

#include <boost/filesystem/operations.hpp>
#include <fstream>
#include <sstream>

static const size_t BUFFER_SIZE = 8192;
static const size_t DIGEST_SIZE = 20;

Hash::Hash() {}

namespace {
    template <class Stream>
    void digest_stream(unsigned char digest[DIGEST_SIZE], Stream &s) {
        char buf[BUFFER_SIZE];
#ifdef WIN32
        HCRYPTPROV prov;
        HCRYPTHASH hash;

        if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
            logging::log(logging::error) << "digest_stream: error CryptAcquireContext" << std::endl;
        }

        if (!CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash)){
            logging::log(logging::error) << "digest_stream: error CryptCreateHash" << std::endl;
        }

        while (s) {
            s.read(buf, sizeof buf);
            std::streamsize extracted = s.gcount();
            if (!CryptHashData(hash, reinterpret_cast<unsigned char *>(buf),
                static_cast<DWORD>(extracted), 0)){
                logging::log(logging::error) << "digest_stream: error CryptHashData" << std::endl;
            }
        }

        //get hash size
        DWORD digest_len = 0;
        DWORD dwCount = sizeof(digest_len);
        if (!CryptGetHashParam(hash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&digest_len), &dwCount, 0)){
            logging::log(logging::error) << "digest_stream: error CryptGetHashParam" << std::endl;
        }

        if (digest_len <= DIGEST_SIZE){
            //now compute the hash
            CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_len, 0);
        }
        else{
            logging::log(logging::error) << "digest_stream: error, digest is bigger than buffer" << std::endl;
        }

        CryptDestroyHash(hash);

        CryptReleaseContext(prov, 0);

#else
        SHA_CTX sc;
        SHA1_Init(&sc);

        while (s) {
            s.read(buf, sizeof buf);
            std::streamsize extracted = s.gcount();
            SHA1_Update(&sc, buf, extracted);
        }
        SHA1_Final(digest, &sc);
#endif
    }
}

Hash::Hash(boost::filesystem::path const &filename) {
    unsigned char digest[DIGEST_SIZE];
    if (boost::filesystem::exists(filename)) {
        std::ifstream f(filename.string().c_str());
        digest_stream(digest, f);
    }
    else {
        std::istringstream s(filename.string());
        digest_stream(digest, s);
    }

    // conversion to string
    static char out[DIGEST_SIZE * 2 + 1];
    for (size_t i = 0; i < DIGEST_SIZE; i++) {
        out[2 * i] = "0123456789abcdef"[(digest[i] >> 4) & 0x0F];
        out[2 * i + 1] = "0123456789abcdef"[(digest[i] >> 0) & 0x0F];
    }
    out[DIGEST_SIZE * 2] = 0;
    digest_ = out;
}

Hash::Hash(std::string const &value) : digest_(value) {}

std::string const &Hash::str() const { return digest_; }
char const *Hash::c_str() const { return digest_.c_str(); }

size_t Hash::size() const { return digest_.size(); }

bool Hash::operator<(Hash const &other) const {
    return digest_ < other.digest_;
}

bool Hash::operator>(Hash const &other) const {
    return digest_ > other.digest_;
}

bool Hash::operator==(Hash const &other) const {
    return digest_ == other.digest_;
}

bool Hash::operator!=(Hash const &other) const {
    return digest_ != other.digest_;
}

std::ostream &operator<<(std::ostream &oss, Hash const &h) {
    return oss << h.str();
}
