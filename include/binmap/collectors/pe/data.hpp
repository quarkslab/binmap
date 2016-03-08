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

#ifndef PE_DATA_HPP_INCLUDED
#define PE_DATA_HPP_INCLUDED

#include "binmap/collectors/pe.hpp"

#include <map>

template <typename _Bits> class PeData {
private:
  std::ifstream &_file;

  PeDosHeader _dos_header;
  PeNtHeadersTraits<_Bits> _nt_headers;
  PeSectionHeaderVector _sections;

public:
  typedef PeNtHeadersTraits<_Bits> PeNtHeaders;

  PeData(std::ifstream &file);
  virtual ~PeData();

  const PeDosHeader &dos_header(void) const { return _dos_header; }
  void dos_header(PeDosHeader &dos_header) { _dos_header = dos_header; }

  const PeNtHeaders &nt_headers(void) const { return _nt_headers; }
  void nt_headers(PeNtHeaders nt_headers) { _nt_headers = nt_headers; }

  const PeSectionHeaderVector &sections(void) const { return _sections; }
  void sections(const PeSectionHeaderVector &sections) { _sections = sections; }

  bool convert_rva_to_offset(uint32_t rva, uint32_t &offset) const;

  bool section_header_from_rva(uint32_t rva, PeSectionHeader &offset) const;

  bool read(uint32_t offset, size_t size, char **buffer) const;
  bool read(uint32_t offset, size_t size, char *buffer) const;
  bool read_line(uint32_t offset, std::string &out_string) const;
};

#endif
