# Create a variable containing all .cpp files
set(files main.c aes.c)

# Add OpenMP flag for compiler
SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -fopenmp)

ADD_DEFINITIONS(-fopenmp)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr ${files})

TARGET_LINK_LIBRARIES(aes_ctr m)





ADD_EXECUTABLE(b64 b64.c)


install(
  TARGETS aes_ctr b64
  RUNTIME DESTINATION bin
)
