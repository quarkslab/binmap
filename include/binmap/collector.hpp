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

#ifndef BINMAP_DEPENDENCY_ANALYZER_HPP
#define BINMAP_DEPENDENCY_ANALYZER_HPP

#include "binmap/metadata.hpp"

#include <string>
#include <set>
#include <memory>
#include <boost/filesystem/path.hpp>

/// \brief A collector collects dependencies and metadata for a given type
/// Derive from this class to implement a collector for a given file type
class Collector {

public:

  virtual ~Collector();
  /// \brief Initialize collector for given \p path
  /// returns false if initialization fails
  virtual bool initialize(boost::filesystem::path const &path) = 0;

  /// \brief Fills \p deps with the absolute path of the dependencies.
  virtual void operator()(std::set<boost::filesystem::path> &deps) = 0;

  /// \brief Fills \p base with the metadata.
  virtual void operator()(MetadataInfo &mi) = 0;

  /// \brief Lazily scans available collectors for one capable to handle \p path
  /// according to Collector::ty_new
  static std::auto_ptr<Collector> get_collector(boost::filesystem::path const &path);

  /// \brief Adds \p collector to the pool of existing collectors
  struct Register {
    Register(std::auto_ptr<Collector>(*collector)());
  };
};

template<class T>
inline std::auto_ptr<Collector> make_collector() {
  return std::auto_ptr<Collector>(new T());
}

#endif
