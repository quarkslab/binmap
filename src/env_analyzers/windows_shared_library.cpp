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

#include "binmap/windows_shared_library.hpp"

#include "binmap/collectors/pe/decoder.hpp"
#include "binmap/log.hpp"

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

#include <string>
#include <fstream>

#ifdef _WIN32
#include <Windows.h>
#include <tchar.h>
#endif

#define WINDOWS_FOLDER  "windows"
#define SYSTEM_FOLDER   "system"
#define SYSTEM32_FOLDER "system32"
#define SYSWOW64_FOLDER "syswow64"
#define WINSXS_FOLDER   "winsxs"

WindowsSharedLibraryLoader::WindowsSharedLibraryLoader(char const type[]) : Env(type){ }

WindowsSharedLibraryLoader::~WindowsSharedLibraryLoader(){}

void WindowsSharedLibraryLoader::fill_apisetschema_cache(std::string const &apisetschema_module, cache_type& cache)
{
    std::ifstream file(apisetschema_module.c_str(), std::ios_base::in | std::ios_base::binary);
    if (!file){
        //TODO: error logging -> file can't be opened
        return;
    }

    //build the cache
    ApiSetMap* apisetmap = new ApiSetMap(file);

    cache_apisetschema_.clear();

    //get the cache
    ApiSetMap::cache_map_t redir_cache = apisetmap->redirections();
    if (!redir_cache.empty()){
        //copy it to our own cache        
        cache_apisetschema_.insert(redir_cache.begin(), redir_cache.end());
    }

    //we don't need the apisetmap instance anymore
    delete apisetmap;
    
}

void WindowsSharedLibraryLoader::fill_cache(std::string const &folder_name, cache_type& cache) {
    if (!boost::filesystem::is_directory(folder_name)){
        return;
    }

    boost::filesystem::directory_iterator end_itr;
    for (boost::filesystem::directory_iterator dir_itr(folder_name); dir_itr != end_itr; ++dir_itr)
    {
        // Skip if not a file
        if (!boost::filesystem::is_regular_file(dir_itr->status())) 
            continue;

        //check extension. WARNING : windows is case unsensitive on that matter!
        std::string extension = dir_itr->path().extension().string();
        if (extension.empty()){
            continue;
        }
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        if (extension == ".dll"){
            //file match the extension: store it in the environement cache.
            std::string filename = dir_itr->path().filename().string();
            std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

            std::string full_path = dir_itr->path().string();
            std::transform(full_path.begin(), full_path.end(), full_path.begin(), ::tolower);

            cache[filename] = full_path;
        }
    }
}

void WindowsSharedLibraryLoader::fill_dir_cache(const boost::filesystem::path &top_folder, dirs_cache_t& cache)
{
    //windows is not case sensitive, so will save all folders in lower case. That'll simplify further search later on.

    //iterate over all directories in top folder, searching for all contained dirs
    std::vector<boost::filesystem::path> matching_dirs;
    boost::filesystem::directory_iterator end_itr;
    for (boost::filesystem::directory_iterator itr(top_folder); itr != end_itr; ++itr){
        //skip if not dir        
        if (!boost::filesystem::is_directory(itr->status())){
            continue;
        }

        std::string current_dir = itr->path().string();
        boost::algorithm::to_lower(current_dir);
        cache.push_back(current_dir);
    }
}

void WindowsSharedLibraryLoader::fill_file_cache(const boost::filesystem::path &directory, files_cache_t& file_cache)
{
    //iterate over all files in top folder, searching for all contained dirs
    std::vector<boost::filesystem::path> matching_dirs;
    boost::filesystem::directory_iterator end_itr;
    for (boost::filesystem::directory_iterator itr(directory); itr != end_itr; ++itr){
        //skip if not file        
        if (!boost::filesystem::is_regular_file(itr->status())){
            continue;
        }

        std::string current_file(itr->path().string());
        boost::algorithm::to_lower(current_file);
        file_cache.push_back(current_file);
    }

}

void WindowsSharedLibraryLoader::find_system_folder(boost::filesystem::path const &root){
    boost::filesystem::path tmp_system_folder;

    if (root.empty())
    {
        // if no root, search for the system folder
        std::string tmp_drive = "C:\\";        

        for (int i = 0; i <= NUM_DRIVE_LETTERS; ++i)
        {
            boost::filesystem::path drive = tmp_drive;
            if (boost::filesystem::is_directory(drive))
            {
                tmp_system_folder = drive / WINDOWS_FOLDER / SYSTEM32_FOLDER;
                if (boost::filesystem::exists(tmp_system_folder)){
                    this->system_disk_ = tmp_drive;
                    this->system_folder_ = tmp_system_folder;
                    break;
                }
            }
            tmp_drive[0]++;
        }

        if (tmp_system_folder.empty())
        {
            /* couldn't find system folder? as a last option, try 'A:\' and 'B:\'
                we didn't tried before because this might access slow disk readers and thus 
                might freeze the process */
            const char* first_drives[] = { "A:", "B:" };
            BOOST_FOREACH(const char* drive, first_drives){
                if (boost::filesystem::exists(drive)) {
                    boost::filesystem::path current_drive = drive;
                    tmp_system_folder = current_drive / WINDOWS_FOLDER / SYSTEM32_FOLDER;
                    if (boost::filesystem::exists(tmp_system_folder)){
                        this->system_disk_ = drive;
                        this->system_folder_ = tmp_system_folder;
                        break;
                    }
                }
            }
        }
    }
    else{
        //environement root is not empty: check if env root contains the system folder
        tmp_system_folder = root / WINDOWS_FOLDER / SYSTEM32_FOLDER;
        if (boost::filesystem::exists(tmp_system_folder)){
            this->system_disk_ = root;
            this->system_folder_ = tmp_system_folder;
        }
        else
        {
            //TODO: [implement this!] env root is not empty but doesn't contain the system folder...

            //idea: we might need to go up and check, on each folder, if we have found the right folder...
        }        
    }

    //check if the current OS is a 64-bit OS
    if (!system_disk_.empty())
    {
        boost::filesystem::path sysow64 = system_disk_ / WINDOWS_FOLDER / SYSWOW64_FOLDER;
        if (boost::filesystem::exists(sysow64)){
            syswow64_ = sysow64;
        }
    }
}

void WindowsSharedLibraryLoader::initialize(boost::filesystem::path const &root){
    /* search for the system folder */
    this->find_system_folder(root);

    if (system_folder_.empty() || system_disk_.empty())
    {
        //TODO: logging -> couldn't find system folders
        return;
    }
       
    /* fill the default search paths.

    We must follow the DLL search order rules,
    see : http://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx
    Note: we suppose that 'SafeDllSearchMode' is enabled because it is on by default on all
    windows systems.

    Search order (default):

    1) The directory from which the application loaded. [Note: can't obvisouly be done statically...]
    2) The system directory. (usually: c:\windows\system32)
    3) The 16-bit system directory. (usually: c:\windows\system)
    4) The Windows directory. (usually: c\windows ; might also be C:\)
    5) The current directory. [will be done in pe.cpp]
    6) The directories that are listed in the PATH environment variable. [Note: can't obvisouly be done statically...]
        Note that this does not include the per-application path specified by the App Paths registry key.
        The App Paths key is not used when computing the DLL search path.
    */

    // set windows folder
    boost::filesystem::path windows = system_disk_ / WINDOWS_FOLDER;

    // set the winSXS directory
    boost::filesystem::path winsxs = windows / WINSXS_FOLDER;
    if (boost::filesystem::is_directory(winsxs)){
        winsxs_ = winsxs;
        fill_dir_cache(winsxs_, cache_dir_winsxs_);
    }

    //set default paths
    boost::filesystem::path system32 = windows / SYSTEM32_FOLDER;
    default_paths_.push_back(system32);
    default_paths_.push_back(windows /  SYSTEM_FOLDER);
    default_paths_.push_back(windows);
    default_paths_.push_back(system_disk_);

    /* fill the default cache */
    BOOST_FOREACH(boost::filesystem::path path, default_paths_){
        fill_cache(path.string(), cache_default_);
    }

    /* if we have a 64 bit OS, then fill the cache for sysWOW64*/
    if (has_wow64())
    {
        syswow64_paths_.push_back(syswow64_);

        /* fill the syswow64 cache */
        BOOST_FOREACH(boost::filesystem::path path, syswow64_paths_){
            fill_cache(path.string(), cache_syswow64_);
        }
    }

    // fill the ApiSetSchema redirection cache, if any.

    void* old_redir;
    if (!disable_redirection(&old_redir)){
        //TODO: error logging -> couldn't disable file redirection
        return;
    }
    boost::filesystem::path apisetschema_module = system32 / "apisetschema.dll";
    if (boost::filesystem::exists(apisetschema_module)){
        fill_apisetschema_cache(apisetschema_module.string(), cache_apisetschema_);
    }

    revert_redirection(old_redir);
}

bool WindowsSharedLibraryLoader::search_in_cache(cache_type const &cache, boost::filesystem::path &path,
    boost::filesystem::path const &file) const
{
    cache_type::const_iterator where = cache.find(file.string());
    if (where != cache.end()) {
        path = where->second;
        return true;
    }
    else
        return false;
}

// check if file is in the default cache: if it is found, set path to its full path and return true (false otherwise).
bool WindowsSharedLibraryLoader::operator()(boost::filesystem::path &path,
    boost::filesystem::path const &file) const {
    return search_in_cache(cache_default_, path, file);
}

bool WindowsSharedLibraryLoader::operator()(boost::filesystem::path &path,
    boost::filesystem::path const &file, PeFileHeader::machine_type_t machine_type) const
{
    cache_type cache;

    //switch on the PE machine type  and get the right DLL cache
    switch (machine_type)
    {
    case PeFileHeader::kMachineI386:
        if (has_wow64()){
            cache = cache_syswow64_;
        }
        else{
            cache = cache_default_;
        }
        break;

    case PeFileHeader::kMachineAmd64:
        cache = cache_default_;
        break;

    default:
        //TODO: login-> unknown machine type.
        break;
    }

    return search_in_cache(cache, path, file);

}

bool WindowsSharedLibraryLoader::disable_redirection(void** old_redir_val) const
{
    bool result = true;

#ifdef _WIN32
    typedef BOOL(WINAPI *WOW64DISABLEWOW64FSREDIRECTION)(PVOID *OldValue);

    HMODULE hk32 = ::GetModuleHandle(_T("kernel32"));
    WOW64DISABLEWOW64FSREDIRECTION pDisableRedir = (WOW64DISABLEWOW64FSREDIRECTION)GetProcAddress(hk32, "Wow64DisableWow64FsRedirection");
    if (pDisableRedir != NULL){
        result = (pDisableRedir(old_redir_val) != FALSE);
    }
    else{
        result = false;
    }
#endif

    return result;
}

bool WindowsSharedLibraryLoader::revert_redirection(void* old_redir_val) const
{
    bool result = true;

#ifdef _WIN32
    //re-enable redirection    
    typedef BOOL(WINAPI *WOW64REVERTWOW64FSREDIRECTION)(PVOID OldValue);
    HMODULE hk32 = ::GetModuleHandle(_T("kernel32"));
    WOW64REVERTWOW64FSREDIRECTION pRevertRedir = (WOW64REVERTWOW64FSREDIRECTION)GetProcAddress(hk32, "Wow64RevertWow64FsRedirection");
    if (pRevertRedir != NULL) {
        result = (pRevertRedir(old_redir_val) != FALSE);
    }
    else{
        result = false;
    }
#endif

    return result;
}


//FIXME: might need to do something about removing the 'staticness' of this variable?
//static windows loader environment variable
static WindowsSharedLibraryLoader win_loader(WINDOWS_SHARED_LIBRARY_LOADER_ENV_NAME);

ApiSetMap::ApiSetMap(std::ifstream &file) : file_(file) {
    // open the PE
    PEDecoder* pe = PeDecoderFactory(file);
    if (pe == NULL){
        return;
    }

    if (pe->is_compatible())
    {
        bool found_section = false;
        PeSectionHeader section_header;
        // search for a section named '.apiset'
        BOOST_FOREACH(const PeSectionHeader& section, pe->sections()){
            std::string secname((char*)(section.Name));
            if (secname == ".apiset")
            {
                found_section = true;
                section_header = section;
                break;
            }
        }

        if (found_section)
        {
            //if found then get the section raw data
            file.seekg(section_header.PointerToRawData, std::ios_base::beg);
            uint8_t* apisetsection = new uint8_t[section_header.SizeOfRawData];
            file.read(reinterpret_cast<char*>(apisetsection), section_header.SizeOfRawData);

            //switch on ApiSetMap version type
            uint32_t* pversion = reinterpret_cast<uint32_t*>(apisetsection);
            switch (*pversion)
            {
            case 2:
                parse_apisetmap_v2(apisetsection);
                break;
            case 4:
                parse_apisetmap_v4(apisetsection);
                break;
            default:
                //TODO: logging or throw or return?
                break;
            }

        }
    }
}

void ApiSetMap::parse_apisetmap_v2(uint8_t* apisetsection){
    //TODO: implement this!
    logging::log(logging::error) << "ApiSetMap::parse_apisetmap_v2: not implemented" << std::endl;
    throw std::runtime_error("ApiSetMap::parse_apisetmap_v2: not implemented");
}

void ApiSetMap::parse_apisetmap_v4(uint8_t* apisetsection){
    ApiSetMap_v4* apisetmap = reinterpret_cast<ApiSetMap_v4*>(apisetsection);

    for (unsigned int i = 0; i < apisetmap->num_structs; ++i)
    {
        //read the string and its length and convert it to std::wstring
        StringDescriptor_v4* string_descriptor = &apisetmap->string_descriptors[i];
        uint32_t offset_virtual_dll_string = string_descriptor->OffsetDllString;
        if (offset_virtual_dll_string != 0)
        {
            wchar_t* wstr = reinterpret_cast<wchar_t*>(apisetsection + offset_virtual_dll_string);
            std::wstring w_redir(wstr, string_descriptor->StringLength / sizeof(wchar_t));
            std::string redir(w_redir.begin(), w_redir.end());

            // go to the redirection
            DLLRedirector_v4* redirector = reinterpret_cast<DLLRedirector_v4*>(apisetsection + string_descriptor->OffsetDllRedirector);
            //the redi goes like this: redir1 -> redir2, thus we're only interested in the second redirection
            uint32_t redirection_offset = redirector->redirections[0].OffsetRedirection2;
            if (redirection_offset != 0)
            {

                wstr = reinterpret_cast<wchar_t*>(apisetsection + redirection_offset);
                std::wstring w_original(wstr, redirector->redirections[0].RedirectionLength2 / sizeof(wchar_t));
                std::string original(w_original.begin(), w_original.end());
                cache_map_[redir] = original;
            }
            else{
                // live debugging test in ntdll!LdrpLoadDll -> If we get here this means that the virtual DLL exists but there's no 'real' DLL to back it.
                // This hapeens at least on Windows 8.1 update 1.
                logging::log(logging::warning) << "ApiSetMap: the virtual DLL " << redir << " has no implentation DLL counterpart." << std::endl;
            }
        }
        else{
            logging::log(logging::error) << "ApiSetMap: descriptor has no offset to virtual dll string." << std::endl;
        }
    }

}
