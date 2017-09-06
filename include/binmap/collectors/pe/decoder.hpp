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

#ifndef PE_DECODER_HPP_INCLUDED
#define PE_DECODER_HPP_INCLUDED

#include "binmap/collectors/pe.hpp"
#include "binmap/collectors/pe/data.hpp"
#include "binmap/metadata.hpp"

#include <boost/filesystem/path.hpp>

#include <vector>
#include <map>

/* \brief decode the PE format
 * uses a template helper class to distinguish 32/64 bits versions, aka PE and
 * PE+
*/

struct PEDecoder {
  virtual ~PEDecoder() {}

  // Tell if the module is a PE module.
  virtual bool is_compatible(void) const = 0;

  // get sections from PE
  virtual const std::vector<PeSectionHeader> &sections(void) const = 0;

  // get all imported modules for a given module
  virtual void
  get_imports(boost::filesystem::path const &module_path,
              std::set<boost::filesystem::path> &imports) const = 0;

  virtual bool get_exports(boost::filesystem::path const &module_path,
                           std::vector<std::string> &exports) const = 0;
  virtual bool get_delay_imports(boost::filesystem::path const &module_path,
				std::vector<std::string> &imported_symbols) const =0;

  virtual bool get_imported_symbols(boost::filesystem::path const &module_path,
                           	    std::vector<std::string> &imported_symbols) const = 0;

  virtual void extract_hardening_features(MetadataInfo&) const = 0;

  static uint16_t machine_type(std::ifstream &file);
};

/* Used to create PEDecoder instances from a given PE file path.*/
PEDecoder *PeDecoderFactory(boost::filesystem::path const &path,
                            bool full_parsing = false);
/* Used to create PEDecoder instances from a given PE file path */
PEDecoder *PeDecoderFactory(std::ifstream &file, bool full_parsing = false);

template <typename _Bits> class pe_decoder : public PEDecoder {
public:
  typedef PeNtHeadersTraits<_Bits> PeNtHeaders;
  typedef PeImageLoadConfigDirectoryTraits<_Bits> PeImageLoadConfigDirectory;

  pe_decoder(std::ifstream &file, bool full_parsing = false);

  bool is_compatible(void) const;
  uint16_t machine_type(void) const;
  bool convert_rva_to_offset(uint32_t rva, uint32_t &offset) const;
  bool convert_rva_to_offset64(uint64_t rva, uint64_t &offset) const;
  void get_imports(boost::filesystem::path const &module_path,
                   std::set<boost::filesystem::path> &imports) const;
  bool get_exports(boost::filesystem::path const &module_path,
                   std::vector<std::string> &exports) const;
  bool get_imported_symbols(boost::filesystem::path const &module_path,
                  	    std::vector<std::string> &imported_symbols) const;

  bool get_delay_imports(boost::filesystem::path const &module_path,
		   std::vector<std::string> &imported_symbols) const;
  void extract_hardening_features(MetadataInfo& mi) const;
  PeNtHeaders const nt_headers(void) const;
  std::vector<PeSectionHeader> const &sections(void) const;
  bool
  parse_manifest(std::map<std::string, boost::filesystem::path> &assembly_maps);
  char *get_section(PeDataDirectory::image_directory_entry_t entry) const;

private:
  PeData<_Bits> _pe_data;
  std::ifstream &_file;
  bool _is_compatible;
  uint16_t _machine_type;
  std::map<std::string, boost::filesystem::path> _assembly_maps;
  bool find_module_path(boost::filesystem::path const &module_path,
                        std::string &imports) const;
};

#endif
