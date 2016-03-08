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

#include "binmap/collectors/pe/resource_parser.hpp"
#include "binmap/windows_shared_library.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>


template <typename _Bits>
ResourceParser<_Bits>::ResourceParser(const PeData<_Bits>* pe_data) : _pe_data(pe_data), _resource_section(NULL)
{
    uint32_t res_rva = _pe_data->nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryResource]
        .VirtualAddress;

    uint32_t res_len =
        _pe_data->nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryResource]
        .Size;

    // set if there are resources or not
    _has_resource = !(res_rva == 0 || res_len == 0);
    if (!_has_resource){
        return;
    }

    uint32_t res_off;
    if (!_pe_data->convert_rva_to_offset(res_rva, res_off)){
        throw std::runtime_error("ResourceParser: bad convert_rva_to_offset");
    }

    //read the whole section
    if (!_pe_data->read(res_off, res_len, &_resource_section)){
        throw std::runtime_error("ResourceParser: couldn't read PE file");
    }

    PeImageResourceDirectory* res_dir = reinterpret_cast<PeImageResourceDirectory*>(_resource_section);

    get_all_resource_dir_entries_for_dir(res_dir, _id_map, _name_map);
}

template <typename _Bits>
ResourceParser<_Bits>::~ResourceParser(){
    if (_resource_section != NULL){
        delete[] _resource_section;
        _resource_section = NULL;
    }
}

template <typename _Bits>
bool ResourceParser<_Bits>::find_entry_by_id(uint16_t id, PeImageResourceDirectoryEntry& dir_entry) const {
    bool result = false;
    std::map<uint16_t, PeImageResourceDirectoryEntry>::const_iterator it = _id_map.find(id);
    if (it != _id_map.end())
    {
        result = true;
        dir_entry = it->second;
    }

    return result;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_all_resource_dir_entries_for_dir(PeImageResourceDirectory* res_dir, map_id_t& id_map, map_name_t& name_map) const
{
    // note: recall that resource entries start with named entries followed by ID entries
    unsigned int max_pos = res_dir->NumberOfNamedEntries + res_dir->NumberOfIdEntries - 1;
    PeImageResourceDirectoryEntry* res_dir_entry = reinterpret_cast<PeImageResourceDirectoryEntry*>(res_dir + 1);

    for (unsigned int current_pos = 0; current_pos <= max_pos; ++current_pos)
    {
        PeImageResourceDirectoryEntry const & current_dir_entry = res_dir_entry[current_pos];

        switch (current_dir_entry.name_type())
        {
        case PeImageResourceDirectoryEntry::NameIsOffset:
        {
            // we have an entry by name
            uint32_t off_string = current_dir_entry.NAMEORIDUNION.Name & 0x7FFFFFFF;
            ImageResourceDirStringU* string_struct = reinterpret_cast<ImageResourceDirStringU*>(&_resource_section[off_string]);
            std::wstring wstr(string_struct->NameString, string_struct->length);
            //FIXME: really need to do better conversion from std::wstring to std::string here
            std::string str(wstr.begin(), wstr.end());
            name_map[str] = current_dir_entry;
        }
            break;
        case PeImageResourceDirectoryEntry::NameIsId:
        {
            // entry name is a 16-bit ID
            uint16_t current_id = current_dir_entry.NAMEORIDUNION.Name;
            id_map[current_id] = current_dir_entry;
        }
            break;
        default:
            //TODO:logging
            break;
        }
    }

    return true;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_all_resource_dir_entries_for_entry(const PeImageResourceDirectoryEntry& entry, map_id_t& id_map, map_name_t& name_map) const {
    //check if the current entry leads to a directory, if not then get out now
    if (entry.data_type() != PeImageResourceDirectoryEntry::DataTypeIsDirectory){
        return false;
    }

    //current entry leads to a directory which gives how much entries we have (in that directory)
    uint32_t offset_dir = entry.OFFSETTODATAUNION.OffsetToData & 0x7FFFFFFF;
    PeImageResourceDirectory* res_dir = reinterpret_cast<PeImageResourceDirectory*>(&_resource_section[offset_dir]);

    return get_all_resource_dir_entries_for_dir(res_dir, id_map, name_map);
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_directory_for_entry(const PeImageResourceDirectoryEntry& entry, PeImageResourceDirectory& directory) const {
    if (entry.data_type() == PeImageResourceDirectoryEntry::DataTypeIsDirectory)
    {
        uint32_t off_dir = entry.OFFSETTODATAUNION.OffsetToData & 0x7FFFFFFF;
        directory = *reinterpret_cast<PeImageResourceDirectory*>(&_resource_section[off_dir]);
        return true;
    }

    return false;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_first_dir_entry_from_dir_entry(const PeImageResourceDirectoryEntry& in_entry, PeImageResourceDirectoryEntry& out_entry, uint32_t& num_entries) const
{
    if (in_entry.data_type() == PeImageResourceDirectoryEntry::DataTypeIsDirectory)
    {
        //get directory from this entry
        uint32_t off_dir = in_entry.OFFSETTODATAUNION.OffsetToData & 0x7FFFFFFF;
        PeImageResourceDirectory const & dir = *reinterpret_cast<PeImageResourceDirectory*>(&_resource_section[off_dir]);

        num_entries = dir.NumberOfIdEntries + dir.NumberOfNamedEntries;

        //get first entry from this directory
        out_entry = *reinterpret_cast<PeImageResourceDirectoryEntry const *>(&dir + 1);
        return true;
    }
    return false;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_data_entry_from_dir_entry(const PeImageResourceDirectoryEntry& dir_entry, PeImageResourceDataEntry& data_entry) const
{

    if (dir_entry.data_type() == PeImageResourceDirectoryEntry::DataTypeIsEntry)
    {
        uint32_t data_entry_off = dir_entry.OFFSETTODATAUNION.OffsetToData;
        data_entry = *reinterpret_cast<PeImageResourceDataEntry*>(&_resource_section[data_entry_off]);
        return true;
    }

    return false;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_data_from_data_entry(const PeImageResourceDataEntry& data_entry, char** buffer) const
{
    //convert RVA to offset (note: data_entry.OffsetToData is a RVA in the PE file!)
    uint32_t off_data_content;
    if (!_pe_data->convert_rva_to_offset(data_entry.OffsetToData, off_data_content)){
        return false;
    }


    //allocate room for output buffer
    *buffer = new char[data_entry.Size];

    //read data
    if (!_pe_data->read(off_data_content, data_entry.Size, buffer)) {
      delete[] *buffer;
      return false;
    }


    return true;
}

template <typename _Bits>
bool ResourceParser<_Bits>::get_data_from_dir_entry(const PeImageResourceDirectoryEntry& dir_entry, char** buffer) const
{
    PeImageResourceDataEntry data_entry;
    bool result = get_data_entry_from_dir_entry(dir_entry, data_entry);
    if (!result){
        return false;
    }

    if (!get_data_from_data_entry(data_entry, buffer)){
        return false;
    }

    return true;
}

#include <istream>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/foreach.hpp>

// see http://akrzemi1.wordpress.com/2011/07/13/parsing-xml-with-boost/

template <typename _Bits>
bool ResourceParser<_Bits>::parse_manifest(std::istream& stream, std::vector<AssemblyIdentity>& vec_asm) const
{
    bool result = true;
    boost::property_tree::ptree pt;
    boost::property_tree::ptree dependency_pt;

    //read xml from stream
    boost::property_tree::read_xml(stream, pt);

    try{
        BOOST_FOREACH(boost::property_tree::ptree::value_type const&v, pt.get_child("assembly")) {
            if (v.first == "dependency")// v.first is the name of the child.
            {
                // v.second is the child tree.
                dependency_pt = v.second;
                BOOST_FOREACH(boost::property_tree::ptree::value_type const& v_dep, dependency_pt.get_child("dependentAssembly")){
                    if (v_dep.first == "assemblyIdentity"){
                        AssemblyIdentity asm_id;

                        //required fields
                        asm_id.type = v_dep.second.get<std::string>("<xmlattr>.type");
                        asm_id.name = v_dep.second.get<std::string>("<xmlattr>.name");
                        asm_id.version = v_dep.second.get<std::string>("<xmlattr>.version");
                        asm_id.publicKeyToken = v_dep.second.get<std::string>("<xmlattr>.publicKeyToken");

                        //optional fiels
                        asm_id.processorArchitecture = v_dep.second.get<std::string>("<xmlattr>.processorArchitecture", "");
                        asm_id.language = v_dep.second.get<std::string>("<xmlattr>.language", "");
                        vec_asm.push_back(asm_id);
                    }
                }
            }
        }
    }
    catch (boost::property_tree::xml_parser_error){
        //TODO: logging
        result = false;
    }

    return result;

}

template <typename _Bits>
bool ResourceParser<_Bits>::get_winsxs_directory_for_assembly(const AssemblyIdentity& asm_id, boost::filesystem::path& dir_path, const uint16_t machine) const
{
    //get the windows' specific environment
    WindowsSharedLibraryLoader windows_env = dynamic_cast<WindowsSharedLibraryLoader&>(Env::get(WINDOWS_SHARED_LIBRARY_LOADER_ENV_NAME));

    boost::filesystem::path winsxs_dir(windows_env.winsxs());
    if (winsxs_dir.string() == ""){
        return false;
    }

    /* start building up the the whole directory name
        see http://blogs.msdn.com/b/jonwis/archive/2005/12/28/507863.aspx for the whole directory naming scheme.
        -> proc-arch_name_public-key-token_version_culture_hash
    */

    std::string dir_name;

    //build 'proc-arch'
    if (asm_id.processorArchitecture == "" || asm_id.processorArchitecture == "*")
    {
        switch (machine){
        case PeFileHeader::kMachineI386:
            dir_name = "x86";
            break;

        case PeFileHeader::kMachineAmd64:
            dir_name = "amd64";
            break;

        default:
            //TODO: log this error -> unknown machine type
            return false;
        }
    }
    else{
        dir_name = asm_id.processorArchitecture;
    }

    //build 'name'
    dir_name += "_" + asm_id.name;

    //build 'public-key-token'
    dir_name += "_" + asm_id.publicKeyToken;

    /* Start searching for the directory: note that we don't search for the precise version yet, 
    just collect the directories that match the current pattern. 

    At that moment we have (as an example):
        dir_name = "x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df" 
    And we are searching for:
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.9600.16384_none_7c55c866aa0c3ff0"
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9600.16384_none_a9f4965301334e09"
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9600.17031_none_a9efdb8b01377ea7"
    */

    std::string searched_dir_lower = dir_name;
    boost::algorithm::to_lower(searched_dir_lower);

    std::vector<boost::filesystem::path> matching_dirs;
    std::vector<boost::filesystem::path>::const_iterator itr = windows_env.winsxs_dirs().begin(), itr_end = windows_env.winsxs_dirs().end();
    while (true){
        itr = std::find_if(itr, itr_end, DirStartsWithComparator(searched_dir_lower));
        if (itr == itr_end){
            break;
        }
        matching_dirs.push_back(*itr);
        ++itr;
    }

    //extract assembly versions from directories
    std::vector<AssemblyVersion> vec_asm;
    BOOST_FOREACH(const boost::filesystem::path& adir, matching_dirs){
        AssemblyVersion ver;
        if (get_version_from_winsxs_directory(adir, ver)){
            vec_asm.push_back(ver);
        }
    }

    //nothing found? bail out!
    if (vec_asm.size() <= 0){
        return false;
    }

    /* 
        search for directory with the right version
    */

    //sort directories by version numbers
    std::sort(vec_asm.begin(), vec_asm.end());

    //search for the right version (must be equal or slightly above the current one)
    AssemblyVersion searched_asm_version(asm_id.version);
    AssemblyVersion found_asm_version;
    BOOST_FOREACH(const AssemblyVersion& version, vec_asm){
        if (version >= searched_asm_version){
            found_asm_version = version;
            break;
        }
    }

    //get the directory
    dir_path = found_asm_version.directory_path();

    return true;

}

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
template <typename _Bits>
bool ResourceParser<_Bits>::get_version_from_winsxs_directory(const boost::filesystem::path& dir_path, AssemblyVersion& version) const
{
    bool result = true;
    try{
        version = AssemblyVersion(dir_path);
    }
    catch (boost::bad_lexical_cast&){ result = false; }
    catch (std::runtime_error&){ result = false; }

    return result;

}


AssemblyVersion::AssemblyVersion(const boost::filesystem::path& dir_full_path) : _dir(dir_full_path)
{
    // extract only the last part of the path (yes it's in "filename" even if there's no filename...)
    boost::filesystem::path last_dir_part = dir_full_path.filename();

    //split this last part using '_' as separator. We must have 6 parts for a winSXS dir.
    std::vector<std::string> dir_parts;
    boost::split(dir_parts, last_dir_part.string(), boost::is_any_of("_"));
    if (dir_parts.size() != 6){
        throw std::runtime_error("AssemblyVersion::AssemblyVersion: wrong directory name format.");
    }

    set_major_minors(dir_parts[3]);
}

AssemblyVersion::AssemblyVersion(const std::string& version)
{
    set_major_minors(version);
}

void AssemblyVersion::set_major_minors(const std::string& version)
{
    //split version using '.' as separator
    std::vector<std::string> num_parts;
    boost::split(num_parts, version, boost::is_any_of("."));
    if (num_parts.size() != 4) {
        throw std::runtime_error("AssemblyVersion::set_major_minors: wrong version number format.");
    }

    uint32_t* versions[] = { &_major, &_minor1, &_minor2, &_minor3 };
    unsigned int index = 0;
    BOOST_FOREACH(const std::string& num_str, num_parts){
        uint32_t n = boost::lexical_cast<uint32_t>(num_str);
        *versions[index] = n;
        ++index;
    }

}

bool operator <(const AssemblyVersion& v1, const AssemblyVersion& v2)
{
    if (v1._major < v2._major){
        return true;
    }
    else if (v1._major == v2._major) {
        if (v1._minor1 < v2._minor1){
            return true;
        }
        else if(v1._minor1 == v2._minor1){
            if (v1._minor2 < v2._minor2){
                return true;
            }
            else if(v1._minor2 == v2._minor2){
                if (v1._minor3 < v2._minor3){
                    return true;
                }
            }
        }
    }

    return false;
}

bool operator >(const AssemblyVersion& v1, const AssemblyVersion& v2)
{
    return !(v1 < v2) && v1 != v2;
}

bool operator ==(const AssemblyVersion& v1, const AssemblyVersion& v2)
{
    return ((v1._major == v2._major) && (v1._minor1 == v2._minor1) &&
        (v1._minor2 == v2._minor2) && (v1._minor3 == v2._minor3));
}

bool operator !=(const AssemblyVersion& v1, const AssemblyVersion& v2)
{
    return !(v1 == v2);
}

bool operator >=(const AssemblyVersion& v1, const AssemblyVersion& v2)
{
    return ((v1 > v2) || (v1 == v2));
}

template class ResourceParser < uint32_t >;
template class ResourceParser < uint64_t >;
