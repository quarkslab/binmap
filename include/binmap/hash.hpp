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

#ifndef BINMAP_HASH_H
#define BINMAP_HASH_H

#include <boost/filesystem/path.hpp>

/// A facility class to digest a file
class Hash {

  std::string digest_;

public:
  Hash();

  /// Builds and store the hash of \p filename, using a SHA1.
  explicit Hash(boost::filesystem::path const &filename);
  explicit Hash(std::string const &value);

  /// Implicit conversion to string
  std::string const &str() const;
  char const *c_str() const;
  size_t size() const;

  /// Comparison operators  @{
  bool operator<(Hash const &other) const;
  bool operator>(Hash const &other) const;
  bool operator==(Hash const &other) const;
  bool operator!=(Hash const &other) const;
  /// }
        template < class Archive >
        void serialize(Archive & ar, unsigned int) {
                ar & digest_;
        }
};

std::ostream &operator<<(std::ostream &, Hash const &);

#endif
