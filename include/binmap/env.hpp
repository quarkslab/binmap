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

#ifndef BINMAP_ENV_HPP
#define BINMAP_ENV_HPP

#include <map>
#include <vector>
#include <string>
#include <boost/filesystem/path.hpp>

/// \brief A facility class to retrieve informations concerning the (potentially
/// chrooted) environment
class Env {

public:
  typedef std::vector<boost::filesystem::path> paths_type;

  /// Associate child class to a given \p keyword.
  Env(char const keyword[]);

  /// Allow to initialize an environment with the path to the chrooted
  /// environment \p root.
  virtual void initialize(boost::filesystem::path const &root) = 0;

  /// Locates \p file in the chroot and sets \p path to its absolute value (out
  /// of the chroot).
  virtual bool operator()(boost::filesystem::path &path,
                          boost::filesystem::path const &file) const = 0;

  /// Yields a container that contains the default location for this env
  virtual paths_type const &default_paths() const = 0;

  /// Retrieve the Env associated to \p keyword.
  static Env &get(char const keyword[]);

  /// Sets \p path to the first absolute path found for \p file looking in \p
  /// paths.
  static bool which(boost::filesystem::path &path, paths_type const &paths,
                    boost::filesystem::path const &file);

  /// Initialize all environment analysers with the path to the chrooted
  /// environment \p root.
  static void initialize_all(boost::filesystem::path const &root);

  /// Retrieve the path to the chrooted environment.
  static boost::filesystem::path const &root();
};

#endif
