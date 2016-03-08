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

#ifndef WINDOWS_SHARED_LIBRARY_LOADER_HPP
#define WINDOWS_SHARED_LIBRARY_LOADER_HPP

#include "binmap/env.hpp"
#include "binmap/collectors/pe.hpp"


#define WINDOWS_SHARED_LIBRARY_LOADER_ENV_NAME "WINDOWS_SYSTEM_ROOT"

// number of drive letters from 'C' to 'Z' (both included)
#define NUM_DRIVE_LETTERS 'Z' - 'B'

class WindowsSharedLibraryLoader :
    public Env
{
private:
    typedef std::map<std::string, std::string> cache_type;
    typedef std::vector<boost::filesystem::path> dirs_cache_t;
    typedef dirs_cache_t files_cache_t;

    //default cache: key = module_name ; value = full_path
    cache_type cache_default_;
    //cache for syswow64 (works the same as the default cache)
    cache_type cache_syswow64_;
    //cache for ApiSetSchema
    cache_type cache_apisetschema_;   

    //path where to search (by default) for libraries
    paths_type default_paths_;
    //path to search for 32-bit libraries on a 64-bit system
    paths_type syswow64_paths_;

    //contains all directories used by winSXS
    dirs_cache_t cache_dir_winsxs_;


    //system disk letter (e.g C:\)
    boost::filesystem::path system_disk_;
    //system folder (e.g C:\windows\system32)
    boost::filesystem::path system_folder_;
    //syswow64 folder ((folder for 32-bit libraries on a 64-bit system) if it exists (usually C:\windows\syswow64)
    boost::filesystem::path syswow64_;
    // winsxs / side-by-side assemblies / fusion folder
    boost::filesystem::path winsxs_;

    //fill the internal cache map
    void fill_cache(std::string const &cache_name, cache_type &cache);

    //fill the internal cache for apisetschema redirection scheme
    void fill_apisetschema_cache(std::string const &apisetschema_module, cache_type& cache);

    // search for 'file' module in 'cache', return true if found and set 'path' to the full module path. Returns false otherwise.
    bool search_in_cache(cache_type const &cache, boost::filesystem::path &path,
        boost::filesystem::path const &file) const;

    // set the windows system folder, whatever the root is.
    void find_system_folder(boost::filesystem::path const &root);

public:
    WindowsSharedLibraryLoader(char const type[]);
    virtual ~WindowsSharedLibraryLoader();

    void initialize(boost::filesystem::path const &root);

    bool operator()(boost::filesystem::path &path,
        boost::filesystem::path const &file) const;

    bool operator()(boost::filesystem::path &path,
        boost::filesystem::path const &file, PeFileHeader::machine_type_t machine_type) const;

    std::vector<boost::filesystem::path> const &default_paths() const {
        return default_paths_;
    }

    /* Disable file system redirection: on windows we must disable filesystem redirection 
        for 32-bit processes searching to access the apisetschema.dll file residing in the 
        64-bit system folder.*/
    bool disable_redirection(void** old_redir_val) const;

    //  Revert file system redirection on windows.
    bool revert_redirection(void* old_redir_val) const;

    //fill a directory cache for a top_directory: the cache is filled with all directories conatined in the top_level dir)
    static void fill_dir_cache(const boost::filesystem::path &top_folder, dirs_cache_t& cache);

    //fill a file cache for a directory: the cache is filled with all files contained in this directory)
    static void fill_file_cache(const boost::filesystem::path &directory, files_cache_t& file_cache);

    // return the system disk letter, if any.
    const boost::filesystem::path& system_disk() const { return system_disk_; }

    //return the system folder (e.g. C:\windows\system32), if any.
    const boost::filesystem::path& system_folder() const { return system_folder_; } 

    //return the syswow64 folder if it exists (e.g. C:\windows\syswow64), otherwise returns an empty path.
    const boost::filesystem::path& syswow64() const { return syswow64_; }

    //return the side-by-side assemblies directory
    const boost::filesystem::path& winsxs() const { return winsxs_; }

    //return the cache for the apisetschema map
    const cache_type& apisetmap_cache() const { return cache_apisetschema_; }

    // return the cache for all winsxs folders
    const dirs_cache_t& winsxs_dirs() const { return cache_dir_winsxs_; }

    // return true if the analyzed OS is a 64-bit OS, false otherwise.
    bool has_wow64() const { return !syswow64_.empty(); }
};

//
//TODO: put everything related to apisetmap inside another header file
//

struct ApiSetMap_v2 {
    //current ApiSetMap version (2)
    uint32_t version;
    // number of structures following
    uint32_t num_structs;
};

struct StringDescriptor_v2 {
    uint32_t OffsetDllString;
    uint32_t StringLength;
    uint32_t OffsetDllRedirector;
};

struct DLLRedirector_v2 {
    uint32_t NumberOfRedirections;
};

struct Redirection_v2 {
    uint32_t OffsetRedirection1;
    uint16_t RedirectionLength1;
    uint16_t padding1_;
    uint32_t OffsetRedirection2;
    uint16_t RedirectionLength2;
    uint16_t padding2_;
};

struct StringDescriptor_v4 {
    uint32_t type;
    uint32_t OffsetDllString;
    uint32_t StringLength;
    uint32_t OffsetDllString2;
    uint32_t StringLength2;
    uint32_t OffsetDllRedirector;
};

struct ApiSetMap_v4 {
    //current ApiSetMap version (4)
    uint32_t version;
    //whole .apiset section size
    uint32_t section_size;
    // reserved (always 0)
    uint32_t reserved;
    // number of structures following
    uint32_t num_structs;
    // array of StringDescriptor_v4
    StringDescriptor_v4 string_descriptors[1];
};

struct Redirection_v4 {
    uint32_t reserved;
    uint32_t OffsetRedirection1;
    uint16_t RedirectionLength1;
    uint32_t OffsetRedirection2;
    uint16_t RedirectionLength2;
};

struct DLLRedirector_v4 {
    uint32_t reserved;
    uint32_t NumberOfRedirections;
    Redirection_v4 redirections[1];
};



class ApiSetMap{
private:
    std::map<std::string, std::string> cache_map_;
    uint32_t version_;
    std::ifstream& file_;

    void parse_apisetmap_v2(uint8_t* apisetsection);
    void parse_apisetmap_v4(uint8_t* apisetsection);

public:
    typedef std::map<std::string, std::string> cache_map_t;

    ApiSetMap(std::ifstream &file);
    virtual ~ApiSetMap() {};

    const cache_map_t& redirections() const { return cache_map_; }
};


#endif
