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

#include "binmap/collectors/pe/data.hpp"

#include <fstream>
#include <iostream>
#include <string>
/**
* \brief Ctor.
*
* \param file Stream to the PE file to be parsed.
*/
template <typename _Bits>
PeData<_Bits>::PeData(std::ifstream& file) : _file(file) {}


/**
* \brief Dtor.
*/
template <typename _Bits>
PeData<_Bits>::~PeData(){
}

/**
* \brief Read the underlying PE file.
*
* \param offset Offset (from beginning of file) where the read starts.
* \param size Size to read from file.
* \param buffer User supplied buffer. On exit, if the method returns true, the buffer is filled with bytes read from the file.
* \return True if the read from the file is successfull, false otherwise. Caller is responsible for freeing the returned buffer.
*/
template <typename _Bits>
bool PeData<_Bits>::read(uint32_t offset, size_t size, char* buffer) const {
    if (buffer == NULL){
        return false;
    }

    if (!_file.seekg(offset, std::ios_base::beg)){
        return false;
    }

    if (!_file.read(buffer, size)){
        return false;
    }

    return true;
}

/**
* \brief Read the underlying PE file.
*
* \param offset Offset (from beginning of file) where the read starts.
* \param size Size to read from file.
* \param buffer On exit, if the method returns true, this parameter is filled with a pointer to a buffer containing the bytes read from the file.
* \return True if the read from the file is successful, false otherwise. Caller is responsible for freeing the returned buffer.
*/
template <typename _Bits>
bool PeData<_Bits>::read(uint32_t offset, size_t size, char** buffer) const{
    if (!_file.seekg(offset, std::ios_base::beg)){
        return false;
    }

    char* tmp_buffer = new char[size];

    if (!_file.read(tmp_buffer, size)){
        delete[] tmp_buffer;
        return false;
    }

    *buffer = tmp_buffer;
    return true;
}

template <typename _Bits>
bool PeData<_Bits>::read_line(uint32_t offset, std::string& out_string) const
{
    _file.seekg(offset, std::ios_base::beg);
    if (!std::getline(_file, out_string, '\0')){
        return false;
    }

    return true;
}

/**
* \brief Convert a Relative Virtual Address (RVA) to an offset in the flat PE disk file.
*
* \param rva The RVA to be converted to a file offset.
* \param offset If the conversion can be made, on exit this parameter is loaded with the offset that coressponds to the given RVA.
* \return True if the conversion from RVA to offset can be made, false otherwise.
*/
template <typename _Bits>
bool PeData<_Bits>::convert_rva_to_offset(uint32_t rva,
    uint32_t &offset) const {

    if (_sections.empty()){
        return false;
    }

    PeSectionHeaderVector::const_iterator end = _sections.end();
    for (PeSectionHeaderVector::const_iterator it = _sections.begin(); it != end;
        ++it) {
        if (rva >= it->VirtualAddress &&
            rva < it->VirtualAddress + it->Misc.VirtualSize) {
            offset = it->PointerToRawData + (rva - it->VirtualAddress);
            return true;
        }
    }
    return false;
}


template <typename _Bits>
bool PeData<_Bits>::convert_rva_to_offset64(uint64_t rva,
    uint64_t &offset) const {

    if (_sections.empty()){
        return false;
    }

    PeSectionHeaderVector::const_iterator end = _sections.end();
    for (PeSectionHeaderVector::const_iterator it = _sections.begin(); it != end;
        ++it) {
        if (rva >= it->VirtualAddress &&
            rva < it->VirtualAddress + it->Misc.VirtualSize) {
            offset = it->PointerToRawData + (rva - it->VirtualAddress);
            return true;
        }
    }
    return false;
}

template <typename _Bits>
bool PeData<_Bits>::section_header_from_rva(uint32_t rva, PeSectionHeader &sec_header) const
{
    PeSectionHeaderVector::const_iterator end = _sections.end();
    for (PeSectionHeaderVector::const_iterator it = _sections.begin(); it != end; ++it) {
        if (rva >= it->VirtualAddress &&
            rva < it->VirtualAddress + it->Misc.VirtualSize) {
            sec_header = *it;
            return true;
        }
    }

    return false;

}

//explicit template instanciation
template class PeData < uint32_t >;
template class PeData < uint64_t >;
