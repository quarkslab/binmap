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

#ifndef BINMAP_VERSION_HPP
#define BINMAP_VERSION_HPP

#include <boost/filesystem/path.hpp>
#include <boost/regex.hpp>
#include <set>

/// \brief utility to automate scanning the memory of a binary for a version
/// number
class VersionScanner {

  boost::regex const &regex_;

public:
  /// \brief Constructs a scanner for the binary named \p binary_name
  VersionScanner(std::string const &binary_name);

  /// \brief Looks for any version string between \p begin and \p end
  /// and add them to \p version.
  void operator()(std::set<std::string> &versions, char const *begin,
                  char const *end);
};

#endif
