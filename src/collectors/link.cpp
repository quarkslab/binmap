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

#include "binmap/collector.hpp"
#include "binmap/metadata.hpp"
#include "binmap/env.hpp"

#include <boost/filesystem.hpp>
#include <ciso646>

class SymLinkCollector : public Collector {
  boost::filesystem::path path_;
public:
  bool initialize(boost::filesystem::path const &input_file) {
    path_ = input_file;
    // a symlink is valid only if the link's target exist and is valid
    if(! boost::filesystem::is_symlink(input_file))
      return false;
    path_ = input_file;
    do {
      try {
        std::set<boost::filesystem::path> deps;
        (*this)(deps);
        path_ = *deps.begin();
      }
      catch (boost::filesystem::filesystem_error const &err) {
        return false;
      }
    }
    while (boost::filesystem::is_symlink(path_));

    // this assert the symlink is pointing to something we know
    if(!Collector::get_collector(path_).get())
      return false;
    // everything is ok
    path_ = input_file;
    return true;
  }

  void operator()(std::set<boost::filesystem::path> &deps) {
    boost::filesystem::path target =
        boost::filesystem::read_symlink(path_);
    if (target.is_absolute())
      target = Env::root() / target;
    else
      target = boost::filesystem::canonical(target, path_.parent_path());

    if (not boost::filesystem::exists(target)) {
      throw boost::filesystem::filesystem_error(
          "dangling symlink", target,
          boost::system::error_code(
              boost::system::errc::no_such_file_or_directory,
              boost::system::system_category()));
    }
    deps.insert(target);
  }
  void operator()(MetadataInfo &mi) {
  // do not compute canonical name, it will be done by the target
  }
};

static Collector::Register registry(&make_collector<SymLinkCollector>);
