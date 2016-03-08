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

#ifndef PE_RESOURCE_PARSER_HPP_INCLUDED
#define PE_RESOURCE_PARSER_HPP_INCLUDED

#include "binmap/collectors/pe.hpp"
#include "binmap/collectors/pe/data.hpp"

#include <boost/filesystem/path.hpp>

#include <map>
#include <string>

// typedefs used by ResourceParser class and methods.
typedef std::map<uint16_t, PeImageResourceDirectoryEntry> map_id_t;
typedef std::map<std::string, PeImageResourceDirectoryEntry> map_name_t;

struct AssemblyIdentity {
  std::string type;
  std::string name;
  std::string version;
  std::string processorArchitecture;
  std::string publicKeyToken;
  std::string language;
};

// looks like this: 6.0.9600.16384
class AssemblyVersion {
private:
  uint32_t _major;
  uint32_t _minor1;
  uint32_t _minor2;
  uint32_t _minor3;

  boost::filesystem::path _dir;

  void set_major_minors(const std::string &str_ver);

public:
  AssemblyVersion(const boost::filesystem::path &dir);
  AssemblyVersion(const std::string &version);
  AssemblyVersion() {}

  uint32_t major() const { return _major; }
  uint32_t minor1() const { return _minor1; }
  uint32_t minor2() const { return _minor2; }
  uint32_t minor3() const { return _minor3; }

  const boost::filesystem::path &directory_path(void) const { return _dir; }

  friend bool operator>(const AssemblyVersion &v1, const AssemblyVersion &v2);
  friend bool operator<(const AssemblyVersion &v1, const AssemblyVersion &v2);
  friend bool operator==(const AssemblyVersion &v1, const AssemblyVersion &v2);
  friend bool operator!=(const AssemblyVersion &v1, const AssemblyVersion &v2);
  friend bool operator>=(const AssemblyVersion &v1, const AssemblyVersion &v2);
};

class DirStartsWithComparator {
private:
  std::string _dir_start;

public:
  explicit DirStartsWithComparator(const std::string &dir_start)
      : _dir_start(dir_start) {}
  inline bool operator()(const boost::filesystem::path &dir_full_path) {
    return this->operator()(dir_full_path.string());
  }
  inline bool operator()(const std::string &dir_full_path) {
    return dir_full_path.find(_dir_start) != std::string::npos;
  }
};

template <typename _Bits> class ResourceParser {
private:
  // data from PE
  const PeData<_Bits> *_pe_data;
  // whole resource section content
  char *_resource_section;
  // tells whether current PE file has a resource section or not.
  bool _has_resource;
  // map for resource directory entries with names
  map_name_t _name_map;
  // map for resource directory entries with IDs
  map_id_t _id_map;

public:
  // ctor
  ResourceParser(const PeData<_Bits> *const pe_data);
  // dtor
  virtual ~ResourceParser();

  // return the associated resource directory entry from an ID.
  bool find_entry_by_id(uint16_t id,
                        PeImageResourceDirectoryEntry &dir_entry) const;
  // given a resource directory entry, return the associated (lower level)
  // resource directory
  bool get_directory_for_entry(const PeImageResourceDirectoryEntry &entry,
                               PeImageResourceDirectory &directory) const;
  // given a resource directory entry, return all resource directory entries
  // from it.
  bool get_all_resource_dir_entries_for_entry(
      const PeImageResourceDirectoryEntry &entry, map_id_t &id_map,
      map_name_t &name_map) const;
  // given a resource directory, return all resource directory entries from it.
  bool get_all_resource_dir_entries_for_dir(PeImageResourceDirectory *dir,
                                            map_id_t &id_map,
                                            map_name_t &name_map) const;
  // given a resource data entry, return the data content assoicated to it.
  bool get_data_from_data_entry(const PeImageResourceDataEntry &data_entry,
                                char **buffer) const;
  // given a resource directory entry, return the first resource directory entry
  // associated to it.
  bool get_first_dir_entry_from_dir_entry(
      const PeImageResourceDirectoryEntry &in_entry,
      PeImageResourceDirectoryEntry &out_entry, uint32_t &num_entries) const;
  // given a resource directory entry, return the resource data entry associated
  // to it.
  bool
  get_data_entry_from_dir_entry(const PeImageResourceDirectoryEntry &dir_entry,
                                PeImageResourceDataEntry &data_entry) const;
  // given a data entry, return data content from it.
  bool get_data_from_dir_entry(const PeImageResourceDirectoryEntry &dir_entry,
                               char **buffer) const;

  bool parse_manifest(std::istream &stream,
                      std::vector<AssemblyIdentity> &vec_asm) const;

  /* WinSXS */
  bool get_winsxs_directory_for_assembly(const AssemblyIdentity &asm_id,
                                         boost::filesystem::path &dir_path,
                                         const uint16_t machine =
                                             PeFileHeader::kMachineI386) const;
  bool
  get_version_from_winsxs_directory(const boost::filesystem::path &dir_path,
                                    AssemblyVersion &version) const;

  // tell whether the current PE file has resources or not.
  bool has_resource(void) const { return _has_resource; }
  // return a pointer to a copy of the resource section.
  char *resource_section(void) const { return _resource_section; }
};

#endif // include guard
