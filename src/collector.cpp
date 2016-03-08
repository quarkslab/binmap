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

/* Implementation file for the collector base class
 *
 * All derived classes lie in collectors/
 */
#include "binmap/collector.hpp"

#include <boost/filesystem/path.hpp>
#include <boost/foreach.hpp>
#include <set>

// returns a set for all collectors
std::set<std::auto_ptr<Collector>(*)()>& get_all_collectors(){
    static std::set<std::auto_ptr<Collector>(*)()>* all_coll_ = new std::set<std::auto_ptr<Collector>(*)()>();
    return *all_coll_;
}

Collector::~Collector() {}

// returns a pointer to the first registered collector capable of handling ``key''
std::auto_ptr<Collector> Collector::get_collector(boost::filesystem::path const &key) {
  BOOST_FOREACH(std::auto_ptr<Collector>(*collector)(), get_all_collectors()) {
      std::auto_ptr<Collector> thecollector = (*collector)();
      if(thecollector->initialize(key))
        return thecollector;
  }
  return std::auto_ptr<Collector>(0);
}

Collector::Register::Register(std::auto_ptr<Collector>(*collector)()) {
    get_all_collectors().insert(collector);
}
