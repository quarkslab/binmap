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
#include <gelf.h>
#include <iostream>

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
    Elf* elf_;
    boost::filesystem::path path_;

public:

  ELFCollector() : fd_(0), elf_(0) {
    if (!initialized) {
      initialized = true;
      /* initialize ELF library
       * mandatory!
       * */
      if (elf_version(EV_CURRENT) == EV_NONE)
        throw std::runtime_error(elf_errmsg(-1));
    }
  }

  bool initialize(boost::filesystem::path const &input_file)
  {
    if (boost::filesystem::is_symlink(input_file))
      return false;

    path_ = input_file;
    if (fd_ = fopen(input_file.c_str(), "r")) {
      int fno = fileno(fd_);
      if (elf_ = elf_begin(fno, ELF_C_READ, 0)) {
        Elf_Kind ek = elf_kind(elf_);
        if (ek != ELF_K_ELF) {
          return false;
        }
      }
    } else {
      return false;
    }
    return true;
  }

  ~ELFCollector() {
    if(elf_) elf_end(elf_);
    if(fd_) fclose(fd_);
  }

  std::string get_interp() {
    GElf_Phdr phdr;
    char *interp = 0;
    for (int index = 0; gelf_getphdr(elf_, index, &phdr); ++index) {
      if (phdr.p_type == PT_INTERP) {
        long curr = ftell(fd_);
        if (fseek(fd_, phdr.p_offset, SEEK_SET))
          throw std::runtime_error(strerror(errno));
        interp = new char[phdr.p_memsz];
        if (fread(interp, 1, phdr.p_memsz, fd_) < phdr.p_memsz)
          throw std::runtime_error("inconsistent ELF header: interp field");
        if (fseek(fd_, curr, SEEK_SET))
          throw std::runtime_error(strerror(errno));
        break;
      }
    }
    if (interp) {
      std::string theinterp(interp);
      delete[] interp;
      return theinterp;
    }
    else
      return "";
  }

  void operator()(std::set<boost::filesystem::path> &deps) {
    /* look for the interpreter
     * there is one for executables and shared libraries
     * but not for static libraries
     */
    GElf_Phdr phdr;
    std::string interp = get_interp();
    if (not interp.empty())
      deps.insert(Env::root() / interp);

    Elf_Scn *scn = 0;
    GElf_Shdr scn_shdr;
    /* Process sections */
    while ((scn = elf_nextscn(elf_, scn))) {

      gelf_getshdr(scn, &scn_shdr);

      /* Only look at SHT_DYNAMIC section */
      if (scn_shdr.sh_type == SHT_DYNAMIC) {
        Elf_Data *data = 0;

        /* Process data blocks in the section */
        while ((data = elf_getdata(scn, data))) {
          GElf_Dyn dyn;
          std::vector<boost::filesystem::path> paths[2];
          std::vector<boost::filesystem::path> &rpaths = paths[0],
                                               &runpaths = paths[1];

          {
            std::vector<std::string> paths_[2];
            std::vector<std::string> &rpaths = paths_[0], &runpaths = paths_[1];

            /* look for rpath or runpath specifications */
            for (int i_dyn = 0;
                 gelf_getdyn(data, i_dyn, &dyn) && dyn.d_tag != DT_NULL;
                 i_dyn++) {
              if (dyn.d_tag == DT_RPATH) {
                const char *rpath =
                    elf_strptr(elf_, scn_shdr.sh_link, dyn.d_un.d_val);
                boost::split(rpaths, rpath, boost::is_any_of(":"));
              } else if (dyn.d_tag == DT_RUNPATH) {
                const char *runpath =
                    elf_strptr(elf_, scn_shdr.sh_link, dyn.d_un.d_val);
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
          /* Process entries in dynamic linking table */
          for (int i_dyn = 0;
               gelf_getdyn(data, i_dyn, &dyn) && dyn.d_tag != DT_NULL;
               i_dyn++) {
            if (dyn.d_tag == DT_NEEDED) {
              boost::filesystem::path path;
              boost::filesystem::path const dep_lib =
                  elf_strptr(elf_, scn_shdr.sh_link, dyn.d_un.d_val);
              /* step 1:  Using the directories specified in the DT_RPATH
               * dynamic
               * section attribute of the binary if present and DT_RUNPATH
               * attribute does not exist.  Use of DT_RPATH is deprecated
               */
              if (runpaths.empty() and not rpaths.empty()) {
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
              if (not runpaths.empty()) {
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
                deps.insert(path);
              else {
                deps.insert(dep_lib);
              }
            }
          }
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
    Elf_Scn *scn = 0;
    GElf_Shdr scn_shdr;
    /* Process sections */
    while ((scn = elf_nextscn(elf_, scn))) {

      gelf_getshdr(scn, &scn_shdr);

      if (scn_shdr.sh_type == SHT_SYMTAB or scn_shdr.sh_type == SHT_DYNSYM) {
        Elf_Data *symtab = elf_getdata(scn, 0);
        long symtab_count = scn_shdr.sh_size / scn_shdr.sh_entsize;
        Elf_Scn *scn = elf_getscn(elf_, scn_shdr.sh_link);
        Elf_Data *data = elf_getdata(scn, 0);
        char* strtab = reinterpret_cast<char*>(data->d_buf);

        for (long i = 0; i < symtab_count; ++i) {
          GElf_Sym sym;
          GElf_Addr addr;
          const char *name;

          gelf_getsym(symtab, i, &sym);
          char *sname = strtab + sym.st_name;
          if(sym.st_shndx == SHN_UNDEF) // U
            mi.add_imported_symbol(sname);
          else if(GELF_ST_BIND(sym.st_info) & STB_GLOBAL or GELF_ST_BIND(sym.st_info) & STB_WEAK)
            mi.add_exported_symbol(sname);
        }
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
    if(is_dyn() and has_phdr()) {
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
    GElf_Ehdr ehdr;
    if(gelf_getehdr(elf_, &ehdr)) {
      return ehdr.e_type == ET_DYN;
    }
    return false;
  }

  bool has_bind_now() {
    Elf_Scn *scn = 0;
    GElf_Shdr scn_shdr;
    /* Process sections */
    while ((scn = elf_nextscn(elf_, scn))) {

      gelf_getshdr(scn, &scn_shdr);

      /* Only look at SHT_DYNAMIC section */
      if (scn_shdr.sh_type == SHT_DYNAMIC) {
        Elf_Data *data = 0;

        /* Process data blocks in the section */
        while ((data = elf_getdata(scn, data))) {
          GElf_Dyn dyn;
          for (int i_dyn = 0; gelf_getdyn(data, i_dyn, &dyn) && dyn.d_tag != DT_NULL;
               i_dyn++) {
            if (dyn.d_tag == DT_BIND_NOW) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  bool has_relro() {
    GElf_Phdr phdr;
    for (int index = 0; gelf_getphdr(elf_, index, &phdr); ++index) {
      if (phdr.p_type == PT_GNU_RELRO ) {
        return true;
      }
    }
    return false;
  }
  bool has_phdr() {
    GElf_Phdr phdr;
    for (int index = 0; gelf_getphdr(elf_, index, &phdr); ++index) {
      if (phdr.p_type == PT_PHDR ) {
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

    int fno = fileno(fd_);
    Elf_Scn *scn = 0;
    GElf_Shdr scn_shdr;
    /* look for rodata sections */
    while ((scn = elf_nextscn(elf_, scn))) {

      gelf_getshdr(scn, &scn_shdr);
      /* thats a .rodata */
      if (scn_shdr.sh_type == SHT_PROGBITS) {
        Elf_Data *data = 0;
        while ((data = elf_getdata(scn, data))) {
          char *buffer = static_cast<char *>(data->d_buf);
          char *buffer_end = buffer + data->d_size;
          version_scanner(versions, buffer, buffer_end);
        }
      }
    }
    if (versions.size() == 1) {
      version = *versions.begin();
    }
  }
};

bool ELFCollector::initialized = false;

static Collector::Register registry(&make_collector<ELFCollector>);
