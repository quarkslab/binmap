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
#include "binmap/log.hpp"
#include "binmap/version.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>

#include <LIEF/ELF.h>

#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>

static char const *elf_extensions[] = { ".so" };
static std::set<std::string> extensions(elf_extensions, elf_extensions +
                            sizeof(elf_extensions) / sizeof(*elf_extensions));
static boost::regex version_regex("^\\d+(\\.\\d+)*$", boost::regex::extended);

static boost::regex fortified_symbol_regex("^__.*chk(@.*)?$", boost::regex::extended);


class ELFCollector : public Collector {

    static bool initialized;
    FILE* fd_;
    Elf_Binary_t* elf_binary_;
    boost::filesystem::path path_;

public:

  ELFCollector() : fd_(0), elf_binary_(0) {
    if (!initialized) {
      initialized = true;
    }
  }

  bool initialize(boost::filesystem::path const &input_file)
  {
    if (boost::filesystem::is_symlink(input_file))
      return false;

    path_ = input_file;
    const char* cpath = path_.string().c_str();
    if (is_elf(cpath)) {
      this->elf_binary_ = elf_parse(cpath);
      std::cout << cpath << std::endl;
      return true;
    } else {
      return false;
    }
    return true;
  }

  ~ELFCollector() {
    if(fd_) fclose(fd_);
    if (this->elf_binary_) elf_binary_destroy(this->elf_binary_);
  }

  std::string get_interp() {
    if (this->elf_binary_->interpreter) {
      return this->elf_binary_->interpreter;
    } else {
      return "";
    }
  }

  void operator()(std::set<boost::filesystem::path> &deps) {
    /* look for the interpreter
     * there is one for executables and shared libraries
     * but not for static libraries
     */

    std::string interp = get_interp();

    if (!interp.empty()) {
      deps.insert(Env::root() / interp);
    }


    Elf_DynamicEntry_t** entries = this->elf_binary_->dynamic_entries;
    std::vector<boost::filesystem::path> paths[2];
    std::vector<boost::filesystem::path> &rpaths   = paths[0],
                                         &runpaths = paths[1];
    {
      std::vector<std::string> paths_[2];
      std::vector<std::string> &rpaths   = paths_[0],
                               &runpaths = paths_[1];

      for (size_t i = 0; entries[i] != NULL; ++i) {
        /* look for rpath or runpath specifications */
        if (entries[i]->tag == DT_RPATH) {
          Elf_DynamicEntry_Rpath_t* entry = reinterpret_cast<Elf_DynamicEntry_Rpath_t*>(entries[i]);
          const char *rpath = entry->rpath;
          boost::split(rpaths, rpath, boost::is_any_of(":"));

        } else if (entries[i]->tag == DT_RUNPATH) {
          Elf_DynamicEntry_RunPath_t* entry = reinterpret_cast<Elf_DynamicEntry_RunPath_t*>(entries[i]);
          const char *runpath = entry->runpath;
          boost::split(runpaths, runpath, boost::is_any_of(":"));
        }
      }

      for (size_t j = 0; j < 2; ++j) {
        paths[j].resize(paths_[j].size());
        for (size_t i = 0; i < paths_[j].size(); i++) {
          boost::replace_all(
            paths_[j][i], "$ORIGIN",
            boost::filesystem::path(path_).parent_path().native());
            paths[j][i] = Env::root() / paths_[j][i];
        }
      }
    }
    for (size_t i = 0; entries[i] != NULL; ++i) {

      if (entries[i]->tag == DT_NEEDED) {
        Elf_DynamicEntry_Library_t* library_entry = reinterpret_cast<Elf_DynamicEntry_Library_t*>(entries[i]);
        boost::filesystem::path path;
        boost::filesystem::path const dep_lib = library_entry->name;
        /* step 1:  Using the directories specified in the DT_RPATH
         * dynamic
         * section attribute of the binary if present and DT_RUNPATH
         * attribute does not exist.  Use of DT_RPATH is deprecated
         */
        if (runpaths.empty() && !rpaths.empty()) {
          if (Env::which(path, rpaths, dep_lib)) {
            deps.insert(path);
            continue;
          }
        }

        /* step 2: Using the environment variable LD_LIBRARY_PATH.  Except
         * if  the  executable is a set-user-ID/set-group-ID binary, in
         * which case it is ignored.
         */

        // NIY

        /* step 3: (ELF  only)  Using the directories specified in the
         * DT_RUNPATH dynamic section attribute of the binary if present.
         */
        if (!runpaths.empty()) {
          if (Env::which(path, runpaths, dep_lib)) {
            deps.insert(path);
            continue;
          }
        }

        /* step 4: From the cache file /etc/ld.so.cache, which contains  a
         * compiled  list  of candidate  libraries  previously  found in
         * the augmented library path.  If, however, the  binary  was
         * linked  with  the  -z  nodeflib  linker  option, libraries in
         * the default library paths are skipped.  Libraries installed in
         * hardware  capability  directories  (see  below)  are  preferred
         * to   other libraries.
         */

        if (Env::get("SHARED_LIBRARY")(path, dep_lib)) {
          deps.insert(path);
          continue;
        }


        /* step 5: In the default path /lib, and then /usr/lib.  If the
         * binary was linked with the -z nodeflib linker option, this step
         * is skipped.
         */
        if (Env::which(path, Env::get("SHARED_LIBRARY").default_paths(),
                       dep_lib))
        {
          deps.insert(path);
        } else if(boost::filesystem::exists(path_.parent_path() / dep_lib)) {
          deps.insert(path_.parent_path() / dep_lib);
        } else {
          deps.insert(dep_lib);
        }

      }
    }

  }

  void operator()(MetadataInfo &mi) {

    std::string canonical_name;
    std::string version;
    extract_canonical_name(canonical_name, version, path_);
    mi.name(canonical_name);

    extract_version(version, canonical_name, path_);

    if (version.empty())
      logging::log(logging::warning) << "unable to find version for: "
                                     << path_ << " as " << canonical_name
                                     << std::endl;
    else
      logging::log(logging::warning) << "found version " << version
                                     << " for: " << path_ << std::endl;
    mi.version(version);
    extract_symbols(mi);
    extract_hardening_features(mi);
  }

private:
  void extract_symbols(MetadataInfo &mi)
  {
    Elf_Symbol_t **dynamic_symbols = this->elf_binary_->dynamic_symbols;
    Elf_Symbol_t **static_symbols = this->elf_binary_->static_symbols;

    for (size_t i = 0; dynamic_symbols[i] != NULL; ++i) {
      if (dynamic_symbols[i]->is_imported) {
        mi.add_imported_symbol(dynamic_symbols[i]->name);
      } else if (dynamic_symbols[i]->is_exported) {
        mi.add_exported_symbol(dynamic_symbols[i]->name);
      }
    }

    for (size_t i = 0; static_symbols[i] != NULL; ++i) {
      if (static_symbols[i]->is_imported) {
        mi.add_imported_symbol(static_symbols[i]->name);
      } else if (static_symbols[i]->is_imported) {
        mi.add_exported_symbol(static_symbols[i]->name);
      }
    }
  }

  struct is_fortified {
    bool operator()(std::string const& symbol) const {
      return boost::regex_match(symbol.c_str(), fortified_symbol_regex);
    }
  };

  void extract_hardening_features(MetadataInfo &mi)
  {
    // feature test strongly inspired from the source code of /usr/bin/hardening-check from the hardening-includes debian package
    if(is_dyn() && has_phdr()) {
      mi.add_hardening_feature(MetadataInfo::POSITION_INDEPENDANT_EXECUTABLE);
    }
    // see http://refspecs.linux-foundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/libc---stack-chk-fail-1.html
    if(mi.imported_symbols().find("__stack_chk_fail") != mi.imported_symbols().end()) {
      mi.add_hardening_feature(MetadataInfo::STACK_PROTECTED);
    }
    if(std::find_if(mi.imported_symbols().begin(), mi.imported_symbols().end(), is_fortified()) != mi.imported_symbols().end()) {
      mi.add_hardening_feature(MetadataInfo::FORTIFIED);
    }
    if(has_relro()) {
      mi.add_hardening_feature(MetadataInfo::READ_ONLY_RELOCATIONS);
    }
    if(has_bind_now()) {
      mi.add_hardening_feature(MetadataInfo::IMMEDIATE_BINDING);
    }

  }
  bool is_dyn() {
    return this->elf_binary_->header.file_type == ET_DYN;
  }

  bool has_bind_now() {
    Elf_DynamicEntry_t **entries = this->elf_binary_->dynamic_entries;
    for (size_t i = 0; entries[i] != NULL; ++i) {
      if (entries[i]->tag == DT_BIND_NOW) {
        return true;
      }
    }
    return false;
  }

  bool has_relro() {
    Elf_Segment_t **segments = this->elf_binary_->segments;
    for (size_t i = 0; segments[i] != NULL; ++i) {
      if (segments[i]->type == PT_GNU_RELRO) {
        return true;
      }
    }
    return false;
  }
  bool has_phdr() {
    Elf_Segment_t **segments = this->elf_binary_->segments;
    for (size_t i = 0; segments[i] != NULL; ++i) {
      if (segments[i]->type == PT_PHDR) {
        return true;
      }
    }
    return false;
  }

  void extract_canonical_name(std::string &canonical_name,
                              std::string &version_hint,
                              boost::filesystem::path const &input_path) const {
    boost::filesystem::path basename = input_path.filename();
    // strip known extensions
    while (extensions.find(basename.extension().string()) !=
           extensions.end()) {
      basename = basename.stem();
    }

    canonical_name = basename.native();

    // force lowercase
    std::transform(canonical_name.begin(), canonical_name.end(),
                   canonical_name.begin(), ::tolower);

    // remove trailing numbers if they look like an ABI version number, ie
    // '-[0-9]+'
    std::string::const_iterator last = canonical_name.end() - 1,
                                first = canonical_name.begin();
    while (last > first && strchr(".0123456789", *last))
      --last;
    if (last != first && *last == '-') {
      version_hint = canonical_name.substr(last - canonical_name.begin() + 1);
      canonical_name = canonical_name.substr(0, last - canonical_name.begin());
    }
  }

  void extract_version(std::string &version, std::string const &canonical_name,
                       boost::filesystem::path const &input_path) const {

    // First try: from the naming scheme
    boost::filesystem::path::string_type const &native = input_path.native();
    static char const needle[] = ".so.";
    size_t rpos = native.rfind(needle);
    if (rpos != boost::filesystem::path::string_type::npos) {
      rpos += sizeof(needle) - 1;
      if (boost::regex_match(native.c_str() + rpos, version_regex)) {
        version = native.c_str() + rpos;
        return;
      }
    }

    // Second try: scan relevant memory sections

    std::set<std::string> versions;
    VersionScanner version_scanner(canonical_name);

    Elf_Section_t **sections = this->elf_binary_->sections;
    for (size_t i = 0; sections[i] != NULL; ++i) {
      if (sections[i]->type == SHT_PROGBITS) {
        version_scanner(versions,
            reinterpret_cast<const char*>(sections[i]->content),
            reinterpret_cast<const char*>(sections[i]->content) + sections[i]->size);
      }
    }

    if (versions.size() == 1) {
      version = *versions.begin();
    }
  }
};

bool ELFCollector::initialized = false;

static Collector::Register registry(&make_collector<ELFCollector>);
