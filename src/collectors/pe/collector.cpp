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
#include "binmap/collectors/pe/decoder.hpp"

#include <fstream>
#include <boost/filesystem.hpp>

class PECollector : public Collector {
  std::ifstream _stream;
  PEDecoder* _pe;
  boost::filesystem::path _path;
public:
  PECollector();
  ~PECollector();
  bool initialize(boost::filesystem::path const &input_file);
  void operator()(std::set<boost::filesystem::path> &deps);
  void operator()(MetadataInfo &mi);
};

PECollector::PECollector() : _pe(0) {
}

bool PECollector::initialize(boost::filesystem::path const &path) {
    if (boost::filesystem::is_symlink(path))
      return false;
    _path = path;
    _stream.open(path.string().c_str(), std::ios_base::binary);
    PeDosHeader dos;
    if(!_stream.read(reinterpret_cast<char*>(&dos), sizeof(dos)) || !dos.is_valid())
      return false;

    _stream.seekg(0);
    if(!(_pe = PeDecoderFactory(_stream, true)))
      return false;
    if(! _pe->is_compatible())
        return false;
    return true;
}

PECollector::~PECollector() {
  if(_pe) delete _pe;
}

void PECollector::operator()(std::set<boost::filesystem::path> &deps) {
  _pe->get_imports(_path, deps);
}


void PECollector::operator()(MetadataInfo &mi) {
    // collect exported functions
  std::vector<std::string> exports;
  _pe->get_exports(_path, exports);
  mi.add_exported_symbols(exports.begin(), exports.end());
  //collect hardening features
  _pe->extract_hardening_features(mi);
}

// static collector
static Collector::Register registry(&make_collector<PECollector>);
