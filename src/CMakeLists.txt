# Create a variable containing all .cpp files
FILE(GLOB files *.cpp)

# Checking compiler flags
include(CheckCXXCompilerFlag)

# Checking if compiler supports C++0x standard
CHECK_CXX_COMPILER_FLAG(-std=c++0x CPP0x)

# If C++0x is supported then use it
if(CPP0x)
    MESSAGE(STATUS "c++0x supported")
    add_definitions(-std=c++0x)
else(CPP0x)
    MESSAGE(STATUS "c++0x NOT supported")
endif(CPP0x)


# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr ${files})

install(
  TARGETS aes_ctr
  RUNTIME DESTINATION bin
)
