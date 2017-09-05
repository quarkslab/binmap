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

#ifndef BINMAP_METADATA_HPP
#define BINMAP_METADATA_HPP

#include "binmap/hash.hpp"

#include <map>
#include <string>
#include <iostream>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/serialization/string.hpp>
#include "boost_ex/serialization/unordered_set.hpp"

class MetadataInfo {

public:
  enum hardening_feature_t {
    POSITION_INDEPENDANT_EXECUTABLE,
    STACK_PROTECTED,
    FORTIFIED,
    READ_ONLY_RELOCATIONS,
    IMMEDIATE_BINDING,

    /* 
    * Portable Executable (PE) Hardening features 
    */
    // Stack cookie / canary Microsoft implementation (a.k.a /GS)
    PE_STACK_PROTECTED,
    // Safe Structured Exception Handler (a.k.a /SAFESEH)
    PE_SAFE_SEH,
    // Dynamic base / Address Space Layout Randomization (a.k.a ASLR)
    PE_DYNAMIC_BASE,
    // High entropy ASLR (a.k.a /HIGHENTROPYVA)
    PE_HIGH_ENTROPY_VA,
    // Code Integrity image (code signing)
    PE_FORCE_INTEGRITY,
    // NX (No Execute) compatible image
    PE_NX_COMPAT,
    // Image should execute in AppContainer
    PE_APPCONTAINER,
    // Image supports Control Flow Guard
    PE_GUARD_CF,
  };

private:
  Hash hash_;
  std::string name_;
  std::string version_;
  boost::unordered_set<std::string> exported_symbols_;
  boost::unordered_set<std::string> imported_symbols_;
  boost::unordered_set<hardening_feature_t> hardening_features_;

public:

  MetadataInfo();

  MetadataInfo(Hash const &hash, std::string const &name = "",
               std::string const &version = "");

  Hash const &hash() const;
  void hash(std::string const &value);

  std::string const &name() const;
  void name(std::string const &value);

  std::string const &version() const;
  void version(std::string const &value);

  boost::unordered_set<std::string> const &exported_symbols() const;
  void add_exported_symbol(std::string const &value);
  template <class Iterator>
  void add_exported_symbols(Iterator begin, Iterator end);

  boost::unordered_set<std::string> const &imported_symbols() const;
  void add_imported_symbol(std::string const &value);
  template <class Iterator>
  void add_imported_symbols(Iterator begin, Iterator end);

  boost::unordered_set<hardening_feature_t> const &hardening_features() const;
  void add_hardening_feature(hardening_feature_t const &value);

  void update(MetadataInfo const &other);

  bool operator!=(MetadataInfo const &other) const;

  bool operator==(MetadataInfo const &other) const;

  template <class Archive> void serialize(Archive &ar, unsigned int) {
    ar &hash_ &name_ &version_ &exported_symbols_ &imported_symbols_ & hardening_features_;
  }
};

std::ostream &operator<<(std::ostream &os, MetadataInfo const &info);

class Metadata {

  boost::unordered_map<std::string, MetadataInfo> db_;

  Metadata(Metadata const &);

public:
  typedef Hash key_type;
  typedef MetadataInfo value_type;

  Metadata();

  void insert(value_type const &info);

  value_type operator[](key_type const &key) const;

  template < class Archive >
  void serialize(Archive & ar, unsigned int) {
      ar & db_;
  }
};

template<class Iterator>
inline void MetadataInfo::add_exported_symbols(Iterator begin, Iterator end)
{
  for(; begin != end; ++begin)
    add_exported_symbol(*begin);
}


template<class Iterator>
inline void MetadataInfo::add_imported_symbols(Iterator begin, Iterator end)
{
  for(; begin != end; ++begin)
    add_imported_symbol(*begin);

}





#endif
