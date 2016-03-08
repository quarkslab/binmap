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

#include "binmap/env.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

#include <inttypes.h>

/* this code is inspired by the format description from
 * eglibc-2.17
 * and most notably elf/cache.c
 */

/* { start of eglibc header */
#define CACHEMAGIC "ld.so-1.7.0"
#define CACHEMAGIC_NEW "glibc-ld.so.cache"
#define CACHE_VERSION "1.1"
#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

/* libc5 and glibc 2.0/2.1 use the same format.  For glibc 2.2 another
 *  format has been added in a compatible way:
 *  The beginning of the string table is used for the new table:
 *       old_magic
 *       nlibs
 *       libs[0]
 *       ...
 *       libs[nlibs-1]
 *       pad, new magic needs to be aligned
 *            - this is string[0] for the old format
 *       new magic - this is string[0] for the new format
 *       newnlibs
 *       ...
 *       newlibs[0]
 *       ...
 *       newlibs[newnlibs-1]
 *       string 1
 *       string 2
 *       ...
 */

struct file_entry {
  int flags;               /* This is 1 for an ELF library.  */
  unsigned int key, value; /* String table indices.  */
};

struct cache_file {
  char magic[sizeof CACHEMAGIC - 1];
  unsigned int nlibs;
  struct file_entry libs[0];
};

struct file_entry_new {
  int32_t flags;       /* This is 1 for an ELF library.  */
  uint32_t key, value; /* String table indices.  */
  uint32_t osversion;  /* Required OS version.	 */
  uint64_t hwcap;      /* Hwcap entry.	 */
};

struct cache_file_new {
  char magic[sizeof CACHEMAGIC_NEW - 1];
  char version[sizeof CACHE_VERSION - 1];
  uint32_t nlibs;       /* Number of entries.  */
  uint32_t len_strings; /* Size of string table. */
  uint32_t unused[5];   /* Leave space for future extensions
                      *  and align to 8 byte boundary.  */
  struct file_entry_new libs[0]; /* Entries describing libraries.  */
  /* After this the string table of size len_strings is found.	*/
};

#ifdef _WIN32
    #define __alignof__ __alignof
#endif

/* Used to align cache_file_new.  */
#define ALIGN_CACHE(addr)                                                      \
  (((addr) + __alignof__(struct cache_file_new) - 1) &                         \
   (~(__alignof__(struct cache_file_new) - 1)))

/* } end of eglibc headers */

class LinuxSharedLibraryLoader : public Env {
  typedef std::map<std::string, std::string> cache_type;
  cache_type cache_;

  paths_type default_paths_;

  void fill_cache(std::string const &cache_name) {
    FILE *f = fopen(cache_name.c_str(), "r");
    if (!f)
      throw std::runtime_error("Can't open cache file" +
                               std::string(cache_name));
    fseek(f, 0, SEEK_END);
    size_t cache_size = ftell(f);
    rewind(f);

    cache_file *cache = (cache_file *)new char[cache_size];
    fread(cache, 1, cache_size, f);

    struct cache_file_new *cache_new = NULL;
    const char *cache_data;
    int format = 0;

    if (memcmp(cache->magic, CACHEMAGIC, sizeof CACHEMAGIC - 1)) {
      /* This can only be the new format without the old one.  */
      cache_new = (struct cache_file_new *)cache;

      if (memcmp(cache_new->magic, CACHEMAGIC_NEW, sizeof CACHEMAGIC_NEW - 1) ||
          memcmp(cache_new->version, CACHE_VERSION, sizeof CACHE_VERSION - 1))
        throw std::runtime_error("File is not a cache file");
      format = 1;
      /* This is where the strings start.  */
      cache_data = (const char *)cache_new;
    } else {
      size_t offset = ALIGN_CACHE(sizeof(struct cache_file) +
                                  (cache->nlibs * sizeof(struct file_entry)));
      /* This is where the strings start.  */
      cache_data = (const char *)&cache->libs[cache->nlibs];

      /* Check for a new cache embedded in the old format.  */
      if (cache_size > (offset + sizeof(struct cache_file_new))) {

        cache_new = (struct cache_file_new *)((char *)cache + offset);

        if (memcmp(cache_new->magic, CACHEMAGIC_NEW,
                   sizeof CACHEMAGIC_NEW - 1) == 0 &&
            memcmp(cache_new->version, CACHE_VERSION,
                   sizeof CACHE_VERSION - 1) == 0) {
          cache_data = (const char *)cache_new;
          format = 1;
        }
      }
    }

    if (format == 0) {
      for (unsigned int i = 0; i < cache->nlibs; i++)
        cache_[cache_data + cache->libs[i].key] =
            (Env::root() / (cache_data + cache->libs[i].value)).string(); //TODO: fix for windows (.native() against string())
    } else if (format == 1) {
      for (unsigned int i = 0; i < cache_new->nlibs; i++)
        cache_[cache_data + cache_new->libs[i].key] =
            (Env::root() / (cache_data + cache_new->libs[i].value)).string();//TODO: fix for windows (.native() against string())
    }
    /* Cleanup.  */
    delete[](char *)cache;
    fclose(f);
  }

public:
  LinuxSharedLibraryLoader(char const type[]) : Env(type) {}

  void initialize(boost::filesystem::path const &root) {
    /* populate the cache */
    boost::filesystem::path cache_path = root / "/etc/ld.so.cache";
    if (boost::filesystem::exists(cache_path))
      fill_cache(cache_path.string());//TODO: fix for windows (.native() against string())

    /* fill the default search path */
    static char const * default_paths[] = {"/lib", "/usr/lib", "/system/lib"};
    BOOST_FOREACH(char const* path, default_paths) {
      boost::filesystem::path fullpath = root / path;
      if(boost::filesystem::exists(fullpath)) {
        default_paths_.push_back(fullpath);
      }
    }
  }

  bool operator()(boost::filesystem::path &path,
                  boost::filesystem::path const &file) const {
    cache_type::const_iterator where = cache_.find(file.string());//TODO: fix for windows (.native() against string())
    if (where != cache_.end()) {
      path = where->second;
      return true;
    } else
      return false;
  }

  std::vector<boost::filesystem::path> const &default_paths() const {
    return default_paths_;
  }
};

static LinuxSharedLibraryLoader loader("SHARED_LIBRARY");
