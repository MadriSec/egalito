# The version.txt file is the official record of the version number. We use the
# contents of that file to set the project version for use in other CMake files.
file(READ "${CMAKE_CURRENT_LIST_DIR}/version.txt" ver)

string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${ver})
set(CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${ver})
set(CPACK_PACKAGE_VERSION_MINOR ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${ver})
set(CPACK_PACKAGE_VERSION_PATCH ${CMAKE_MATCH_1})
set(CPACK_PACKAGE_VERSION 
    ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})

set(CPACK_INSTALL_COMMANDS "make -f relocate.mk")
set (CPACK_PACKAGE_NAME "egalito")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_LIST_DIR}/README")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "An egalitarian binary recompiler and transformer")
set(CPACK_PACKAGE_VENDOR "Grammatech Inc.")
set(CPACK_PACKAGE_CONTACT egalito@grammatech.com)
set(CPACK_PACKAGE_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_LIST_DIR}/LICENSE")

set(CPACK_INSTALLED_DIRECTORIES CMAKE_CURRENT_LIST_DIR "cpack")
set(CPACK_PROJECT_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/cpack-config.cmake)

