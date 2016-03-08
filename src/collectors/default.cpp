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
#include <boost/filesystem/operations.hpp>
#include <ciso646>

class DefaultCollector : public Collector {
public:
  // the default collector only takes care of files that do not exist
  bool initialize(boost::filesystem::path const &input_file) {
    return not boost::filesystem::exists(input_file)
        // symlinks are not real files, right?
        and not boost::filesystem::is_symlink(input_file);
  }

  // never find any dependency, the file does not exists :-/
  void operator()(std::set<boost::filesystem::path> &) {}

  // do not add any info, as we cannot collect any
  void operator()(MetadataInfo& mi) {
  }
};

static Collector::Register registry(&make_collector<DefaultCollector>);
