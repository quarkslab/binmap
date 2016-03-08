# defines
#
# GELF_FOUND - system has libelf
# GELF_INCLUDE_DIR - the libelf include directory
# GELF_LIBRARIES - The libraries needed to use libelf

find_library(GELF_LIBRARIES elf)
find_path(GELF_INCLUDE_DIR gelf.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GElf DEFAULT_MSG GELF_LIBRARIES GELF_INCLUDE_DIR)
