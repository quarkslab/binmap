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

#ifndef BINMAP_LOG_HPP
#define BINMAP_LOG_HPP

#include <iostream>

namespace logging {

/// logging levels, in decreasing level of severity.
enum verbosity_level {
  error,
  warning,
  info,
};

/// Simplistic logging facility
class Log {
  verbosity_level current_level_; /// Logging level, default is
                                  /// verbosity_level::error
public:
  Log();
  /// Update verbosity level, only message of lower or equal value are logged.
  void set(verbosity_level);
  /// Stream accessor, log all messaged sent to the stream if \p is lower or
  /// equal to current_level_.
  std::ostream &operator()(verbosity_level);
};

/// global logger to be used for logging
extern Log log;
}

#endif
