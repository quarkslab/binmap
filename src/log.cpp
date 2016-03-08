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

#include "binmap/log.hpp"

namespace logging {

Log log;

Log::Log() : current_level_(error) {}

void Log::set(verbosity_level lvl) { current_level_ = lvl; }

static std::ostream cnull(0);

std::ostream &Log::operator()(verbosity_level lvl) {
  if (lvl > current_level_)
    return cnull;
  else
    return std::clog;
}
}
