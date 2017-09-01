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

#include "binmap/metadata.hpp"
#include "binmap/log.hpp"

#include <stdexcept>
#include <cstdio>
#include <ciso646>

MetadataInfo::MetadataInfo() {}

MetadataInfo::MetadataInfo(Hash const &hash, std::string const &name,
                           std::string const &version
                           )
    : hash_(hash), name_(name), version_(version) {}

Hash const &MetadataInfo::hash() const { return hash_; }
void MetadataInfo::hash(std::string const &value) { hash_ = Hash(value); }

std::string const &MetadataInfo::name() const { return name_; }
void MetadataInfo::name(std::string const &value) { name_ = value; }

std::string const &MetadataInfo::version() const { return version_; }
void MetadataInfo::version(std::string const &value) { version_ = value; }

boost::unordered_set<std::string> const &MetadataInfo::exported_symbols() const { return exported_symbols_; }
void MetadataInfo::add_exported_symbol(std::string const &value) { exported_symbols_.insert(value); }

boost::unordered_set<std::string> const &MetadataInfo::imported_symbols() const { return imported_symbols_; }
void MetadataInfo::add_imported_symbol(std::string const &value) { imported_symbols_.insert(value); }

boost::unordered_set<MetadataInfo::hardening_feature_t> const &MetadataInfo::hardening_features() const { return hardening_features_; }
void MetadataInfo::add_hardening_feature(hardening_feature_t const &value) { hardening_features_.insert(value); }

bool MetadataInfo::operator!=(MetadataInfo const &other) const {
  return hash_ != other.hash_
      or name_ != other.name_
      or version_ != other.version_
      or exported_symbols_ != other.exported_symbols_
      or imported_symbols_ != other.imported_symbols_
      or hardening_features_ != other.hardening_features_;
}

bool MetadataInfo::operator==(MetadataInfo const &other) const {
  return !((*this) != other);
}

void MetadataInfo::update(MetadataInfo const &info) {
  if (name_.empty())
    name_ = info.name();
  else if (!info.name().empty() && name() != info.name())
    logging::log(logging::warning)
        << "found different canonical names for sha1 `" << hash_
        << "': " << name_ << " vs. " << info.name_ << std::endl;

  if (version_.empty())
    version_ = info.version();
  else if (!info.version().empty() && version() != info.version())
    logging::log(logging::warning) << "found different versions for sha1 `"
                                   << hash_ << "': " << version_ << " vs. "
                                   << info.version_ << std::endl;

  if(imported_symbols_.empty())
    imported_symbols_ = info.imported_symbols();
  else if(!info.imported_symbols().empty() && imported_symbols() != info.imported_symbols())
    logging::log(logging::warning) << "found different versions for imported_symbols"
                                   << std::endl;

  if(exported_symbols_.empty())
    exported_symbols_ = info.exported_symbols();
  else if(!info.exported_symbols().empty() && exported_symbols() != info.exported_symbols())
    logging::log(logging::warning) << "found different versions for exported_symbols"
                                   << std::endl;

  if(hardening_features_.empty())
    hardening_features_ = info.hardening_features();
  else if(!info.hardening_features().empty() && hardening_features() != info.hardening_features())
    logging::log(logging::warning) << "found different versions for hardening_features"
                                   << std::endl;
}

Metadata::Metadata() {}

void Metadata::insert(MetadataInfo const &info) {
  Hash const &hash = info.hash();
  std::string const& key = hash.str();
  boost::unordered_map<std::string, MetadataInfo> :: iterator where = db_.find(key);
  if (where != db_.end()) {
    where->second.update(info);
  } else {
    db_[key] = info;
  }
}

Metadata::value_type Metadata::operator[](key_type const &key) const {
  boost::unordered_map<std::string, MetadataInfo> :: const_iterator where = db_.find(key.str());
  if( where != db_.end())
    return where->second;
  else
    throw std::runtime_error("key not found");
}

std::ostream &operator<<(std::ostream &os, MetadataInfo const &info) {
  os << info.name() << ": " << info.hash();
  if (!info.version().empty())
    os << '[' << info.version() << ']';
  if (!info.exported_symbols().empty())
    os << '(' << info.exported_symbols().size() << " exported symbols)";
  if (!info.imported_symbols().empty())
    os << '(' << info.imported_symbols().size() << " imported symbols)";
  if (!info.hardening_features().empty())
    os << '(' << info.hardening_features().size() << " hardening features)";
  return os << std::endl;
}
