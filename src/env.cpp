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

/* implementation for the Env base class
 *
 * derived classes lie in env/
 */
#include "binmap/env.hpp"

#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <boost/filesystem.hpp>

// these two functions are declared in this form to avoid the static initialization order fiasco
// it relies on the fact that static variables inside a function are only initialized the first time the function is called
static std::map<std::string, Env *>& get_envs() {
  static std::map<std::string, Env *> *the_envs = new std::map<std::string, Env *>();
  return *the_envs;
}

static boost::filesystem::path&  get_root() {
  static boost::filesystem::path *the_root = new boost::filesystem::path();
  return *the_root;
}


// base constructor, registers derived class as handler for ``type''
Env::Env(char const type[]) { get_envs()[type] = this; }

// get a reference to the env analyzer in charge of the given ``type''
Env &Env::get(char const type[]) { return *get_envs()[type]; }

// functor used to find the first matching entry when searching a file in a path
namespace {
struct FileFinder {

  boost::filesystem::path const &target_;

  FileFinder(boost::filesystem::path const &target) : target_(target) {}

  bool operator()(boost::filesystem::path const &dir) const {
    boost::filesystem::path target_candidate = dir / target_;
    return boost::filesystem::exists(target_candidate);
  }
};
}

// resolve filename ``file'' against PATH ``paths'' and write the result in ``path'' if found
// returns false if not found
bool Env::which(boost::filesystem::path &path, paths_type const &paths,
                boost::filesystem::path const &file) {
  paths_type::const_iterator found =
      std::find_if(paths.begin(), paths.end(), FileFinder(file));

  if (found != paths.end()) {
    path = boost::filesystem::canonical(*found / file);
    return true;
  } else
    return false;
}

// functor to dispatch call to initialize
namespace {
struct initializer {
  boost::filesystem::path const &root_;
  initializer(boost::filesystem::path const &root) : root_(root) {}
  void operator()(std::pair<std::string, Env *> const &iter) const {
    iter.second->initialize(root_);
  }
};
}

// call ``initialize'' with parameter ``root'' on each Env analyzer
void Env::initialize_all(boost::filesystem::path const &root) {
  get_root() = root;
  std::for_each(get_envs().begin(), get_envs().end(), initializer(root));
}

// get the base of current file hierarchy.
boost::filesystem::path const &Env::root() { return get_root(); }
