# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/cryptyrust_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/cryptyrust_autogen.dir/ParseCache.txt"
  "cryptyrust_autogen"
  )
endif()
