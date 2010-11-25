# Add OpenMP flag for compiler
SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -fopenmp)

ADD_DEFINITIONS(-fopenmp -Wall)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr main.c plugin.c)

TARGET_LINK_LIBRARIES(aes_ctr m dl)


ADD_EXECUTABLE(b64 b64.c)
SET_TARGET_PROPERTIES(
    b64
    PROPERTIES
    COMPILE_FLAGS -DSTANDALONE_BUILD
)


ADD_EXECUTABLE(aes_test test.c aes.c)
TARGET_LINK_LIBRARIES(aes_test m)


ADD_EXECUTABLE(md5 md5driver.c md5.c)

ADD_LIBRARY(hash_md5 SHARED hash_md5.c md5.c)

install(
  TARGETS aes_ctr b64 md5
  RUNTIME DESTINATION bin
)
