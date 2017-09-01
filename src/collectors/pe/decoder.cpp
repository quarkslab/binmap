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

/**
* \file pe_decoder.cpp
* \brief Portable Executable reader / parser.
* \author S.R, K.S
* \version 1.0
* \date 2014-07
*
* Portable Executable (PE) reader / parser.
*
*/
#include "binmap/collectors/pe/decoder.hpp"

#include "binmap/log.hpp"
#include "binmap/windows_shared_library.hpp"
#include "binmap/collectors/pe/resource_parser.hpp"

#include <fstream>

#include <boost/foreach.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>

/**
* \brief Factory function for PEDecoder class.
*
* \param path Full path of file to be opened and parsed.
* \param full_parsing If set to false, only PE headers will be parsed, otherwise internal tables will also be parsed.
* \return Pointer to an instance of the class PEDecoder.
*/
PEDecoder* PeDecoderFactory(boost::filesystem::path const &path, bool full_parsing){

    std::ifstream file(path.string().c_str(), std::ios_base::binary);
    if (!file){
        throw std::runtime_error("couldn't open required PE file.");
    }

    PEDecoder* pe = PeDecoderFactory(file, full_parsing);

    return pe;
}

/**
* \brief Factory function for PEDecoder class.
*
* \param file A file stream to the file to be parsed.
* \param full_parsing If set to false, only PE headers will be parsed, otherwise internal tables will also be parsed.
* \return Pointer to an instance of the class PEDecoder.
*/
PEDecoder* PeDecoderFactory(std::ifstream& file, bool full_parsing){
    uint16_t machine = PEDecoder::machine_type(file);

    PEDecoder* pe;
    switch (machine) {
    case PeFileHeader::kMachineI386:
        pe = new pe_decoder<uint32_t>(file, full_parsing);
        break;

    case PeFileHeader::kMachineAmd64:
        pe = new pe_decoder<uint64_t>(file, full_parsing);
        break;

    default:
        return 0;
    }

    return pe;
}

/**
* \brief Get the machine type of a PE file.
*
* \param file A file stream to the file to be checked.
* \return The machine type (as from IMAGE_FILE_HEADER::File).
*/
uint16_t PEDecoder::machine_type(std::ifstream& file){
    PeDosHeader dos;
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));

    uint16_t machine;
    file.seekg(dos.e_lfanew + sizeof(uint32_t /*PeFileHeader::Signature*/), std::ios_base::beg);

    if (!file.read(reinterpret_cast<char*>(&machine), sizeof(machine)))
        throw std::runtime_error("invalid PE");

    file.seekg(0, std::ios_base::beg);

    return machine;
}

/**
* \brief Construct an new pe_decoder instance.
*
* \param file A file stream to the file to be opened and parsed.
* \param full_parsing If set to false, only PE headers will be parsed, otherwise internal tables will also be parsed.
*/
template <typename _Bits>
pe_decoder<_Bits>::pe_decoder(std::ifstream &file, bool full_parsing)
    : _pe_data(file), _file(file), _is_compatible(false)
{
    // read IMAGE_DOS_HEADER
    PeDosHeader dos;
    if (!_pe_data.read(0, sizeof(PeDosHeader), reinterpret_cast<char*>(&dos))){
        throw std::runtime_error("pe_decoder::ctor: coudl'nt read dos header.");
    }
    if (!dos.is_valid()){
        throw std::runtime_error("pe_decoder::ctor: dos header not valid.");
    }
    _pe_data.dos_header(dos);

    // read IMAGE_NT_HEADERS (support PE/PE+)
    PeNtHeaders nt_headers;
    if (!_pe_data.read(dos.e_lfanew, sizeof(nt_headers), reinterpret_cast<char*>(&nt_headers))){
        throw std::runtime_error("pe_decoder::ctor: couldn't read nt_headers");
    }
    if (!nt_headers.is_valid())
        throw std::runtime_error("pe_decoder::ctor: nt_headers is not valid");

    _pe_data.nt_headers(nt_headers);

    _machine_type = nt_headers.FileHeader.Machine;

    // read all IMAGE_SECTION_HEADER
    PeSectionHeaderVector sections;

    uint16_t scn_no = nt_headers.FileHeader.NumberOfSections;
    sections.reserve(scn_no);
    uint64_t scn_off = dos.e_lfanew +
        offsetof(PeNtHeaders, FileHeader.SizeOfOptionalHeader) + 4 + // +4 for uint32_t Signature?
        nt_headers.FileHeader.SizeOfOptionalHeader;

    for (uint16_t scn_idx = 0; scn_idx < scn_no; ++scn_idx) {
        PeSectionHeader scn_hdr;
        if (!_pe_data.read(static_cast<uint32_t>(scn_off + scn_idx * sizeof(scn_hdr)),
            sizeof(scn_hdr),
            reinterpret_cast<char*>(&scn_hdr))){
            throw std::runtime_error("pe_decoder::ctor: couldn't read section header.");
        }
        sections.push_back(scn_hdr);
    }

    _pe_data.sections(sections);

    if (full_parsing){
        parse_manifest(_assembly_maps);
    }

    _is_compatible = true;
}

/**
* \brief Get NT Headers from PE header.
*/
template <typename _Bits>
const PeNtHeadersTraits<_Bits> pe_decoder<_Bits>::nt_headers(void) const {
    return _pe_data.nt_headers();
}

/**
* \brief Get section headers from PE header.
*/
template <typename _Bits>
const std::vector<PeSectionHeader>& pe_decoder<_Bits>::sections(void) const {
    return _pe_data.sections();
}

/**
* \brief Tell if the current PE is a well-formed PE.
* \return True if the PE header is well_formed, false otherwise.
*/
template <typename _Bits>
bool pe_decoder<_Bits>::is_compatible(void) const {
    return _is_compatible;
}

template <typename _Bits>
uint16_t pe_decoder<_Bits>::machine_type(void) const{
    return _machine_type;
}

/**
* \brief Get the section content for the requested section.
*
* \param entry A section index in the data directory.
* \return The requested section content as an array of char* (or NULL if the section doesn't exist). Caller is responsible for freeing the returned buffer.
*/
template <typename _Bits>
char* pe_decoder<_Bits>::get_section(PeDataDirectory::image_directory_entry_t entry) const{
    uint32_t sec_rva = _pe_data.nt_headers().OptionalHeader.DataDirectory[entry].VirtualAddress;
    uint32_t sec_len = _pe_data.nt_headers().OptionalHeader.DataDirectory[entry].Size;

    if (sec_rva == 0 || sec_len == 0){
        return 0;
    }

    uint32_t sec_off;
    if (!convert_rva_to_offset(sec_rva, sec_off)){
        return 0;
    }


    char* buffer = new char[sec_len];

    _file.seekg(sec_off, std::ios_base::beg);

    if (!_file.read(buffer, sec_len)){
        // critical error: can't read PE file...
        delete[] buffer;
        return 0;
    }

    return buffer;
}

/**
* \brief Parse the imported functions.
*
* \param module_path Module name for which to search for imports.
* \param imports On return, this vector is filled with paths to imported modules.
*/
template <typename _Bits>
void pe_decoder<_Bits>::get_imports(boost::filesystem::path const &module_path, std::set<boost::filesystem::path> &imports) const {
    uint32_t imp_rva =
       _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryImport]
        .VirtualAddress;
    uint32_t imp_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryImport]
        .Size;

    if (imp_rva == 0x0 || imp_len == 0x0)
    {
        //check if this module is part of the apisetschema redirection scheme
        //    in this case there's no import table, we'll do the redirection statically.
        std::string module_filename = module_path.filename().string();
        if (boost::starts_with(module_filename, WINDOWS_APISETSCHEMA_API_START) ||
            boost::starts_with(module_filename, WINDOWS_APISETSCHEMA_EXT_START))
        {
            std::string empty;
            find_module_path(module_path, empty);
            return;
        }
        else{
            // not a redirection scheme and no import table...
            // Note: do NOT throw, we might have modules that do not export anything!
            logging::log(logging::error) << "module " << module_path << " has no import table." << std::endl;
            return;
        }
    }

    uint32_t imp_off;
    if (!convert_rva_to_offset(imp_rva, imp_off))
        throw std::runtime_error("pe_decoder: bad convert_rva_to_offset");

    // set NULL import descriptor
    uint32_t dll_name_off;
    PeImportDescriptor imp_desc, imp_end;
    ::memset(&imp_end, 0x0, sizeof(imp_end));

    do{
        //read import descriptor
        _file.seekg(imp_off, std::ios_base::beg);
        if (!_file.read(reinterpret_cast<char*>(&imp_desc), sizeof(imp_desc))){
            // critical error: can't read PE file...
            throw std::runtime_error("pe_decoder: couldn't read import descriptor");
        }

        imp_off += sizeof(imp_desc);

        if (!convert_rva_to_offset(imp_desc.Name, dll_name_off)){
            //check if this is the NULL import descriptor
            if (::memcmp(&imp_desc, &imp_end, sizeof(PeImportDescriptor)) == 0) {
                // we parsed all import descriptors, we can break safely
                break;
            }
            else{
                //serious error : we should always be able to convert rva to offset
                throw std::runtime_error("pe_decoder: couldn't convert import name rva to offset");
            }
        }

        std::string dll_name;
        _file.seekg(dll_name_off, std::ios_base::beg);
        if (!std::getline(_file, dll_name, '\0')){
            logging::log(logging::error) << "couldn't read name offset for module " << module_path
                << " at offset " << std::hex << dll_name_off << std::endl;
            continue;
        }

        if (dll_name.empty()){
            logging::log(logging::error) << "import name for module " << module_path
                << " at offset " << std::hex << dll_name_off << " is empty." << std::endl;
            continue;
        }

        //names are case unsensitive on windows!
        std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), ::tolower);

	boost::filesystem::path full_path;
        // try to resolve full module path
        if (!find_module_path(module_path, dll_name)){
            logging::log(logging::warning) << "couldn't find full path for module " << dll_name
                << " imported by module " << module_path << std::endl;
		full_path = Env::root() / "./" / dll_name;
		logging::log(logging::warning) << "dll name:" << full_path << "\n";
        }else{

        //push module into imports (even if we couldn't find its full path).
        	full_path = module_path;
	}
        imports.insert(full_path);


    } while (::memcmp(&imp_desc, &imp_end, sizeof(PeImportDescriptor)));


	uint32_t delay_imports_rva =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryDelayImport]
        .VirtualAddress;
    uint32_t delay_imports_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryDelayImport]
        .Size;

    if (delay_imports_rva == 0 || delay_imports_len == 0){
        return;
    }

    uint32_t delay_imports_off;
    if (!convert_rva_to_offset(delay_imports_rva, delay_imports_off))
        throw std::runtime_error("pe_decoder::get_delay_imports: bad convert_rva_to_offset");


    int step = sizeof(_pe_data.nt_headers().OptionalHeader.ImageBase);
    uint32_t name_off=1;
    while(name_off!=0){
	name_off=0;
	PeImageDelayImport delay_imports_dir;
	if (!_pe_data.read(delay_imports_off, sizeof(PeImageDelayImport), reinterpret_cast<char*>(&delay_imports_dir))) {
		throw std::runtime_error("pe_decoder::get_delay_imports: couldn't read delay_imports directory");
	}

	if(delay_imports_dir.szName == 0){
		return;
	}

	if (!convert_rva_to_offset(delay_imports_dir.szName, name_off)){
		return;
	}

	//TODO : associate name + ordinal + func pointer !
	std::string dep_name;
	if (!_pe_data.read_line(name_off, dep_name)){
	    //continue;
	}else{
		logging::log(logging::info) << "find delay_import dependencie: " << dep_name <<"\n";
	}


	std::transform(dep_name.begin(), dep_name.end(), dep_name.begin(), ::tolower);


	boost::filesystem::path full_path;
        // try to resolve full module path
        if (!find_module_path(module_path, dep_name)){
            logging::log(logging::warning) << "couldn't find full path for module " << dep_name
                << " imported by module " << module_path << std::endl;
		full_path = Env::root() / "./" / dep_name;
		logging::log(logging::warning) << "dll name:" << full_path << "\n";
        }else{

        //push module into imports (even if we couldn't find its full path).
        	full_path = module_path;// Env::root() / dll_name;
	}
        imports.insert(full_path);

	delay_imports_off += sizeof(PeImageDelayImport);
    }
}





/**
* \brief Parse the resources.
*
* \param imports On return, this vector si filled with paths to imported modules.
*/
#include <sstream>
#include <iostream>
template <typename _Bits>
bool pe_decoder<_Bits>::parse_manifest(std::map<std::string, boost::filesystem::path>& assembly_maps) {
    /* here comes the tedious parsing of the resource section...
     --> We search for the RT_MANIFEST data content.

    The big picture goes like this:
        - RDIR   = Resource Directory       (RDIR might have one or more RDIRE)
        - RDIRE  = Resource Directory Entry (RDIRE points either to another RDIR or RDATAE)
        - RDATAE = Resource Data Entry      (RDATAE points to data content: bytes that make the resource itself)

    (note: only RT_MANIFEST branch is unfolded)

    *RDIR
      |____ RDIRE Name 'FOO'
      |____ RDIRE Name 'BLA'
      |____ RDIRE ID 1
      |____ ...
      |____ RDIRE ID 24         // note: 24 = RT_MANIFEST
            |_____ RDIR
                    |_____ RDIRE ID 1
                            |_____RDIR
                                    |_____RDIRE ID 1033
                                            |_____ RDATAE --(offset, size, codepage)--> (resource content)

    The code starts  by getting the entry 24 (RT_MANFIEST) with parser.find_entry_by_id().
    Once it's done, and if the entry is found, the code goes in an optimistic parsing:
    The code searches only for the first entry (although there technically can be more than one
    sub-entry and sub-sub-entry, etc.). In the above pic, this means that each RDIR (under 'RDIRE ID 24')
    might possibly have more than one RDIRE although I haven't been able to find a single PE file with more
    than one entry under the RT_MANIFEST entry, though.
    */


    ResourceParser<_Bits> parser (&_pe_data);

    PeImageResourceDirectoryEntry manifest_entry;
    //check if there is an entry for the manifest
    if (!parser.find_entry_by_id(RT_MANIFEST, manifest_entry)){
        return false;

    }
    // entry must be a "resource directory entry"
    if (manifest_entry.data_type() != PeImageResourceDirectoryEntry::DataTypeIsDirectory){
        logging::log(logging::warning) <<
            "pe_decoder::parse_resources: RT_MANIFEST doesn't lead to directory."
            << std::endl;
        return false;
    }

    //get first sub entry for RT_MANIFEST
    PeImageResourceDirectoryEntry sub_entry;
    uint32_t num_entries;
    if (!parser.get_first_dir_entry_from_dir_entry(manifest_entry, sub_entry, num_entries)){
        logging::log(logging::error) <<
            "pe_decoder::parse_resources: error getting sub-entry for RT_MANIFEST."
            << std::endl;
        return false;
    }

    //we might have missed other entries...
    if (num_entries > 1){
        logging::log(logging::warning) <<
            "pe_decoder::parse_resources: more than one sub-entry for RT_MANIFEST."
            << std::endl;
    }

    PeImageResourceDirectoryEntry sub_sub_entry;
    if (!parser.get_first_dir_entry_from_dir_entry(sub_entry, sub_sub_entry, num_entries)){
        logging::log(logging::error) <<
            "pe_decoder::parse_resources: error getting sub-sub-entry for RT_MANIFEST."
            << std::endl;
        return false;
    }

    //we might have missed other entries...
    if (num_entries > 1){
        logging::log(logging::warning) <<
            "pe_decoder::parse_resources: more than one sub-entry for RT_MANIFEST ???"
            << std::endl;
    }

    PeImageResourceDataEntry data_entry;
    if(!parser.get_data_entry_from_dir_entry(sub_sub_entry, data_entry)){
        logging::log(logging::error) <<
            "pe_decoder::parse_resources: could'nt get data entry from entry."
            << std::endl;
        return false;
    }

    //buffer is filled with the content of the manifestfile (XML file)
    char* buffer;
    if (!parser.get_data_from_data_entry(data_entry, &buffer)){
        logging::log(logging::error) <<
            "pe_decoder::parse_resources: couldn't get data from data entry."
            << std::endl;
        return false;
    }

    std::string str_xml(buffer, data_entry.Size);
    delete [] buffer;
    std::istringstream stream(str_xml);


    //parse buffer: return AssemblyIdenty instances from the parsed XML
    std::vector<AssemblyIdentity> asm_vec;
    if (parser.parse_manifest(stream, asm_vec))
    {
        //for each AssemblyIdenty
        boost::filesystem::path dir_path;
        std::vector<boost::filesystem::path> file_cache;
        BOOST_FOREACH(const AssemblyIdentity& asm_id, asm_vec){
            //given an assemblyIdentity, return the corressponding WinSXS folder
            if (parser.get_winsxs_directory_for_assembly(asm_id, dir_path, this->machine_type())){
                // get file(s) inside this folder.
                WindowsSharedLibraryLoader::fill_file_cache(dir_path, file_cache);
                BOOST_FOREACH(const boost::filesystem::path &file, file_cache){
                    //fill assembly map. Key is file name, value is full path with file name: [filename] = full_filename_path
                    boost::filesystem::path const &filename = file.filename();
                    assembly_maps[filename.string()] = dir_path / filename;
                }
            }
        }
    }

    return true;
}

/**
* \brief Search for the full module path given only a file name.
*
* \param containing_module_path Full path to the module (if any) that imports the module in module_name parameter.
* \param module_name On method entry, this is the module file name to search for. On exit, contains the module full path (if found).
* \return True if the full module path for module_name parameter has been found, false otherwise.
*/
template <typename _Bits>
bool pe_decoder<_Bits>::find_module_path(boost::filesystem::path const &containing_module_path, std::string &module_name) const
{
    //get the windows' specific environment
    WindowsSharedLibraryLoader windows_env = dynamic_cast<WindowsSharedLibraryLoader&>(Env::get(WINDOWS_SHARED_LIBRARY_LOADER_ENV_NAME));

    bool result = false;
    boost::filesystem::path full_path;

    PeFileHeader::machine_type_t machine = static_cast<PeFileHeader::machine_type_t>(_pe_data.nt_headers().FileHeader.Machine);

    //check if this module is part of the apisetschema redirection scheme: if not parse as usual.
    if (!boost::starts_with(module_name, WINDOWS_APISETSCHEMA_API_START) &&
        !boost::starts_with(module_name, WINDOWS_APISETSCHEMA_EXT_START))
    {
        //check if the module is part of winSXS redirection
        std::map<std::string, boost::filesystem::path>::const_iterator asm_it = _assembly_maps.find(module_name);
        if (asm_it != _assembly_maps.end())
        {
            module_name = asm_it->second.string();
            result = true;
        }

        //otherwise, search for the module full path, given the current env.
        else if (result = windows_env(full_path, module_name, machine) == true){
            module_name = full_path.string();
        }
        else{
            //we need to search the current folder of the module (if the module is not found in known folders from Env)
            // for this we have the full containing module path (that is, the module from wich module_name is imported).
            boost::filesystem::path containing_module_dir = containing_module_path.parent_path();
            if (!containing_module_dir.empty())
            {
                Env::paths_type paths;
                paths.push_back(containing_module_dir);

                // check if module_name is in current directory.
                boost::filesystem::path out_path;
                if (result = windows_env.which(out_path, paths, module_name))
                {
                    //found the module in the current directory!
                    module_name = out_path.string();
                }
            }
        }
    }
    else{
        // While parsing imported modules from system modules we might find system modules starting with 'api-' or 'ext-'.
        // These system modules are resolved using the apisetmap cache.

        //remove 'api-' or 'ext-' and '.dll'
        std::string module_name_no_prefix = module_name.substr(4, module_name.length() - 4);
        std::string module_name_no_prefix_no_ext = module_name_no_prefix.substr(0, module_name_no_prefix.length() - 4);
        //search DLL redirection in the cache
        std::map<std::string, std::string> cache = windows_env.apisetmap_cache();
        std::map<std::string, std::string>::iterator it = cache.find(module_name_no_prefix_no_ext);
        if (it != cache.end()){
            //if redirection found in cache then search for the full redirection path.
            if (result = windows_env(full_path, it->second, machine) == true){
                std::string real_module_name (full_path.string());
                /*
                logging::log(logging::info) << containing_module_path << " is importing " << module_name <<
                    " by apisetschema redirection. (redirects to: " << real_module_name << " )" << std::endl;
                */
                module_name = real_module_name;
            }
        }
    }

    return result;
}

/*****************************************
	GET_IMPORTED_SYMBOLS
*****************************************/

template <typename _Bits>
bool pe_decoder<_Bits>::get_imported_symbols(boost::filesystem::path const &module_path, std::vector<std::string> &imported_symbols) const {
	logging::log(logging::info) <<"start_imported_symbols\n";
    uint32_t imp_rva =
       _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryImport]
        .VirtualAddress;
    uint32_t imp_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryImport]
        .Size;

    if (imp_rva == 0x0 || imp_len == 0x0)
    {
        //check if this module is part of the apisetschema redirection scheme
        //    in this case there's no import table, we'll do the redirection statically.
        std::string module_filename = module_path.filename().string();
        if (boost::starts_with(module_filename, WINDOWS_APISETSCHEMA_API_START) ||
            boost::starts_with(module_filename, WINDOWS_APISETSCHEMA_EXT_START))
        {
            std::string empty;
            find_module_path(module_path, empty);
	    logging::log(logging::warning) << "Apisetschema redirection scheme\n";
            return false;
        }
        else{
            // not a redirection scheme and no import table...
            // Note: do NOT throw, we might have modules that do not export anything!
            logging::log(logging::error) << "module " << module_path << " has no import table." << std::endl;
            return false;
        }
    }

	uint32_t imp_off;
	if (!convert_rva_to_offset(imp_rva, imp_off)){
		logging::log(logging::error) << "pe_decoder: bad convert_rva_to_offset"<< std::endl;
		throw std::runtime_error("pe_decoder: bad convert_rva_to_offset");
	}
	PeImportDescriptor imp_desc, imp_end;
	::memset(&imp_end, 0x0, sizeof(imp_end));
	do{

        //read import descriptor
        _file.seekg(imp_off, std::ios_base::beg);
        if (!_file.read(reinterpret_cast<char*>(&imp_desc), sizeof(imp_desc))){
		logging::log(logging::error) << "pe_decoder: couldn't read import descriptor"<< std::endl;
            // critical error: can't read PE file...
            throw std::runtime_error("pe_decoder: couldn't read import descriptor");
        }

        imp_off += sizeof(imp_desc);

/****************************************************
PeImportDescriptor _imp_dep;
_imp_dep.FirstThunk => rva to offset => rva to offset bis => skip 2 char + read
***************************************************/
	uint32_t thunk_off;
	if(imp_desc.OriginalFirstThunk==0){
		logging::log(logging::info) <<"out_imported_symbols\n";
		return true;
	}
	if (!convert_rva_to_offset(imp_desc.OriginalFirstThunk, thunk_off)){
		printf("FirstThunk rva : %08x\n", imp_desc.OriginalFirstThunk);
		logging::log(logging::error) << "pe_decoder: couldn't convert import FirstThunk rva to offset"<< std::endl;
		return false;
	}

//readThe Function RVA on the FristThunk :
//TODO : make a function in data.cpp
	
	int step = sizeof(_pe_data.nt_headers().OptionalHeader.ImageBase);
	uint64_t func_rva=1;
	char func_buff[64];
	uint64_t func_off=0;
	bool bad_convert=false;

	while(func_rva != 0){
		func_rva=0;
		func_off=0;
		bool bad_convert=false;
		std::string func_name;

		if (!_file.seekg(thunk_off, std::ios_base::beg)){
			logging::log(logging::error) << "pe_decoder: couldn't go to thunk offset"<< std::endl;
			return false;
		}

		if(!_file.read(func_buff, step)){
			logging::log(logging::error) << "pe_decoder: couldn't find function name rva"<< std::endl;
			return false;
		}
	

		for (int k=0; k<step; k++){
			func_rva += (uint64_t)(func_buff[k]+256)%256 * (int)(pow(256,k));
		}

		if(func_rva ==0){
			logging::log(logging::info) << "func_rva=0\n";
			break;
		}
		
		if (!convert_rva_to_offset64(func_rva, func_off)){
			logging::log(logging::info) << "Imported : N/A\n";
			bad_convert=true;
		}
	
		if(bad_convert == false){
			func_off += 2;	

			if (!_pe_data.read_line(func_off, func_name)){
				logging::log(logging::error) << "couldn't read function name from dll (imported_symbols)"
				<< " at offset " << std::hex << func_off << std::endl;
				func_name="";
			    	continue;
			}else{

				logging::log(logging::info) << "find imported symbol: " << func_name <<"\n";
				imported_symbols.push_back(func_name);
			}
		}
		thunk_off += step;
		bad_convert=false;
	}

    } while (::memcmp(&imp_desc, &imp_end, sizeof(PeImportDescriptor)));
	logging::log(logging::info) <<"out_imported_symbols\n";
	return true;
}

template <typename _Bits>
bool pe_decoder<_Bits>::get_delay_imports(const boost::filesystem::path  &module_path, std::vector<std::string> &imported_symbols) const
{
	logging::log(logging::info) <<"start_delay_imports\n";
    uint32_t delay_imports_rva =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryDelayImport]
        .VirtualAddress;
    uint32_t delay_imports_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryDelayImport]
        .Size;

    if (delay_imports_rva == 0 || delay_imports_len == 0){
	logging::log(logging::info) <<"no_delay_import: out\n";
        return false;
    }

    uint32_t delay_imports_off;
    if (!convert_rva_to_offset(delay_imports_rva, delay_imports_off)){
	logging::log(logging::error) << "pe_decoder::get_delay_imports: bad convert_rva_to_offset"<< std::endl;
        return false;
	}

    int step = sizeof(_pe_data.nt_headers().OptionalHeader.ImageBase);
    uint32_t name_off=1;
    while(name_off!=0){
	name_off=0;
	PeImageDelayImport delay_imports_dir;
	if (!_pe_data.read(delay_imports_off, sizeof(PeImageDelayImport), reinterpret_cast<char*>(&delay_imports_dir))) {
		logging::log(logging::error) << "pe_decoder::get_delay_imports: couldn't read delay_imports directory"<< std::endl;
		return false;
	}

	if(delay_imports_dir.szName == 0){
		logging::log(logging::info) <<"out_delay_imports: name_off = 0\n";
		return true;
	}

	if (!convert_rva_to_offset(delay_imports_dir.szName, name_off)){
		return false;
	}

	//TODO : associate name + ordinal + func pointer !
	std::string dep_name;
	if (!_pe_data.read_line(name_off, dep_name)){
	    //continue;
	}else{
		logging::log(logging::info) << "find delay_import dependencie: " << dep_name <<"\n";
	}

	uint64_t func_rva=1;
	uint64_t func_off=0;
	char func_buff[64];
	std::string func_name;
	uint32_t pINT;
	if (!convert_rva_to_offset(delay_imports_dir.pINT, pINT)){
		logging::log(logging::error) << "pe_decoder: couldn't convert import FirstThunk rva to offset"<< std::endl;
		return false;
	}

	while(func_rva != 0){
		func_rva=0;
		func_off=0;

		if (!_file.seekg(pINT, std::ios_base::beg)){
			logging::log(logging::error) << "pe_decoder: couldn't find function name rva (delay_import)-go to pINT"<< std::endl;
			return false;
		}

		if(!_file.read(func_buff, step)){
			logging::log(logging::error) << "pe_decoder: couldn't find function name rva (delay_import)"<< std::endl;
			return false;
		}

		for (int k=0; k<step; k++){
			func_rva += (func_buff[k]+0x100)%0x100 * (pow(0x100,k));
		}

		if(func_rva !=0){

			if (!convert_rva_to_offset64(func_rva, func_off)){
				logging::log(logging::warning) << "WARNING : couldn't convert function rva to offset, pINT=" << pINT <<std::endl;
			}else{
				func_off += 2;	

				if (!_pe_data.read_line(func_off, func_name)){
					logging::log(logging::error) << "couldn't read function name from dll "
					<< " at offset " << std::hex << func_off << std::endl;
					func_name="";
					//continue;
				}else{

					logging::log(logging::info) << "find imported function (delay_load): " << func_name <<"\n";
					imported_symbols.push_back(func_name);
				}
			}
		}
		pINT += step;
	}
	logging::log(logging::info) <<"out_delay_imports\n";
	delay_imports_off += sizeof(PeImageDelayImport);
    }
    return true;

}

/************************************************************/
/************************************************************/
/************************************************************/
/************************************************************/

/**
* \brief Get all exported functions for a given module.
*
* \param module_path name of the module to be checked for exported functions.
* \param exports On exit, it is filled with exported functions.
* \return True if exported functions has been extracted from the module, false otherwise.
*/
template <typename _Bits>
bool pe_decoder<_Bits>::get_exports(const boost::filesystem::path  &module_path, std::vector<std::string> &exports) const
{
    uint32_t exp_rva =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryExport]
        .VirtualAddress;
    uint32_t exp_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryExport]
        .Size;

    if (exp_rva == 0 || exp_len == 0){
        return false;
    }

    uint32_t exp_off;
    if (!convert_rva_to_offset(exp_rva, exp_off))
        throw std::runtime_error("pe_decoder::get_exports: bad convert_rva_to_offset");

    PeImageExportDirectory export_dir;
    if (!_pe_data.read(exp_off, sizeof(PeImageExportDirectory), reinterpret_cast<char*>(&export_dir))) {
        throw std::runtime_error("pe_decoder::get_exports: couldn't read export directory");
    }

    /* notes:
    total number of functions exported: PeImageExportDirectory::NumberOfFunctions
    total number of function exported by name:  PeImageExportDirectory::NumberOfNames
    total number of function exported by ordinal:  PeImageExportDirectory::NumberOfFunctions - PeImageExportDirectory::NumberOfNames
    */


    //get offset to ordinal table
    uint32_t off_name_ord;
    if (!convert_rva_to_offset(export_dir.AddressOfNameOrdinals, off_name_ord)){
        return false;
    }

    // read ordinal table
    uint16_t* ordinal_table;
    if (!_pe_data.read(off_name_ord,
        export_dir.NumberOfFunctions * sizeof(uint16_t),
        reinterpret_cast<char**>(&ordinal_table))){
        return false;
    }
    delete [] ordinal_table;

    //get offset to name table
    uint32_t off_names;
    if (!convert_rva_to_offset(export_dir.AddressOfNames, off_names)){
        return false;
    }

    // read the whole name table (each entry is an RVA [32-bit] to a char* string)
    uint32_t* names_table;
    if (!_pe_data.read(off_names,
        export_dir.NumberOfNames * sizeof(uint32_t),
        reinterpret_cast<char**>(&names_table))){
        return false;
    }

    logging::log(logging::info) << "Nb of exported_symbol (name): " << export_dir.NumberOfNames << std::endl;

    for (unsigned int i = 0; i < export_dir.NumberOfNames; ++i){
        //get RVA to func name in names table and convert this RVA to an offset
        uint32_t rva_to_name = names_table[i];
        uint32_t off_to_name;
        if (!convert_rva_to_offset(rva_to_name, off_to_name)){
            continue;
        }

        //TODO : associate name + ordinal + func pointer !
        std::string func_name;
        if (!_pe_data.read_line(off_to_name, func_name)){
	    logging::log(logging::info) << "can't read name" << std::endl;
            continue;
        }

	logging::log(logging::info) << "exported_symbol: " << func_name << std::endl;
        exports.push_back(func_name);
    }

    delete[] names_table;

    return true;

}

/**
* \brief Get hardening features (protections) that can be discovered statically in the PE file.
* \param hardening_features Vector of PE hardening features that will be filled by this function.
*/
template <typename _Bits>
void pe_decoder<_Bits>::extract_hardening_features(MetadataInfo &mi) const {

    // first, check protections from DllCharacteristics in image_optional_header
    uint16_t characteristics = _pe_data.nt_headers().OptionalHeader.DllCharacteristics;
    if (characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
        mi.add_hardening_feature(MetadataInfo::PE_HIGH_ENTROPY_VA);
    if (characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        mi.add_hardening_feature(MetadataInfo::PE_DYNAMIC_BASE);
    if (characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        mi.add_hardening_feature(MetadataInfo::PE_FORCE_INTEGRITY);
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        mi.add_hardening_feature(MetadataInfo::PE_NX_COMPAT);
    if (characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
        mi.add_hardening_feature(MetadataInfo::PE_APPCONTAINER);
    if (characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        mi.add_hardening_feature(MetadataInfo::PE_GUARD_CF);

    // check other protections from load configuration directory
    uint32_t load_config_rva =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryLoadConfig]
        .VirtualAddress;

    uint32_t load_config_len =
        _pe_data.nt_headers().OptionalHeader.DataDirectory[PeDataDirectory::kEntryLoadConfig]
        .Size;

    if (load_config_rva != 0 && load_config_len != 0) {
        // read image load configuration directory (support PE/PE+)
        uint32_t load_config_off;
        if (convert_rva_to_offset(load_config_rva, load_config_off)){
            PeImageLoadConfigDirectory ilcd;
            if (!_pe_data.read(load_config_off, sizeof(ilcd), reinterpret_cast<char*>(&ilcd))){
                throw std::runtime_error("pe_decoder::extract_hardening_features: couldn't read image load configuration directory");
            }

            //check /GS (stack cookie / canary)
            if (ilcd.ImageLoadConfigDirectory.SecurityCookie != 0) {
                mi.add_hardening_feature(MetadataInfo::PE_STACK_PROTECTED);
            }

            // check SEH. It can only be present if NO_SEH is 0
            if ((characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0){
                // if Handler count and handler table, then /SAFESEH is present
                if (ilcd.ImageLoadConfigDirectory.SEHandlerCount != 0 && ilcd.ImageLoadConfigDirectory.SEHandlerTable != 0)
                    mi.add_hardening_feature(MetadataInfo::PE_SAFE_SEH);
            }
        }
    }
}

/**
* \brief Convert a Relative Virtual Address (RVA) to an offset in the flat PE disk file.
*
* \param rva The RVA to be converted to a file offset.
* \param offset If the conversion can be made, on exit this parameter is loaded with the offset that corresponds to the given RVA.
* \return True if the conversion from RVA to offset can be made, false otherwise.
*/
template <typename _Bits>
bool pe_decoder<_Bits>::convert_rva_to_offset(uint32_t rva,
    uint32_t &offset) const {
    return _pe_data.convert_rva_to_offset(rva, offset);
}

template <typename _Bits>
bool pe_decoder<_Bits>::convert_rva_to_offset64(uint64_t rva,
    uint64_t &offset) const {
    return _pe_data.convert_rva_to_offset64(rva, offset);
}

// explicit template specialisation
template class pe_decoder < uint32_t >;
template class pe_decoder < uint64_t >;
