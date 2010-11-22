# Create a variable containing all .cpp files
FILE(GLOB files *.c)

# Add OpenMP flag for compiler
SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -fopenmp)

ADD_DEFINITIONS(-fopenmp)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr ${files})

TARGET_LINK_LIBRARIES(aes_ctr m)

install(
  TARGETS aes_ctr
  RUNTIME DESTINATION bin
)
