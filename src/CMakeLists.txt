# Add OpenMP flag for compiler
SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -fopenmp)

ADD_DEFINITIONS(-fopenmp -Wall)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr main.c plugin.c aes.c)
TARGET_LINK_LIBRARIES(aes_ctr m dl rt)


ADD_EXECUTABLE(aes_test test.c aes.c)
TARGET_LINK_LIBRARIES(aes_test m rt)


#ADD_EXECUTABLE(b64 b64.c)
#SET_TARGET_PROPERTIES(
#    b64
#    PROPERTIES
#    COMPILE_FLAGS -DSTANDALONE_BUILD
#)

# ADD_EXECUTABLE(md5 md5driver.c md5.c)


FIND_PACKAGE(MPI)
MESSAGE(${MPI_INCLUDE_PATH})
MESSAGE(${MPI_LIBRARY})
INCLUDE_DIRECTORIES(${MPI_INCLUDE_PATH})
ADD_EXECUTABLE(aes_mpi main_mpi.c aes.c plugin.c)
TARGET_LINK_LIBRARIES(aes_mpi ${MPI_LIBRARY})



ADD_LIBRARY(hash_md5 SHARED hash_md5.c md5.c)

install(
    TARGETS aes_ctr aes_test hash_md5 aes_mpi
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

install(
    PROGRAMS test_thread.sh
    DESTINATION bin
)


