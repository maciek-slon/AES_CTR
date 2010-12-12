# Add OpenMP flag for compiler
#SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -fopenmp)

ADD_DEFINITIONS(-Wall)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr main.c plugin.c aes.c)
TARGET_LINK_LIBRARIES(aes_ctr m dl rt)
SET_TARGET_PROPERTIES(
    aes_ctr
    PROPERTIES
    COMPILE_FLAGS "-fopenmp"
    LINK_FLAGS "-fopenmp"
)


ADD_EXECUTABLE(aes_test test.c aes.c)
TARGET_LINK_LIBRARIES(aes_test m rt dl)


#ADD_EXECUTABLE(b64 b64.c)
#SET_TARGET_PROPERTIES(
#    b64
#    PROPERTIES
#    COMPILE_FLAGS -DSTANDALONE_BUILD
#)

# ADD_EXECUTABLE(md5 md5driver.c md5.c)


#FIND_PACKAGE(MPI)
#MESSAGE("${MPI_INCLUDE_PATH}")
#MESSAGE("${MPI_LIBRARY}")
#MESSAGE("${MPI_LIBRARIES}")
#MESSAGE("${MPI_COMPILE_FLAGS}")
#MESSAGE("${MPI_LINK_FLAGS}")
#INCLUDE_DIRECTORIES(${MPI_INCLUDE_PATH})
ADD_EXECUTABLE(aes_mpi main_mpi.c aes.c plugin.c)
#TARGET_LINK_LIBRARIES(aes_mpi ${MPI_LIBRARY} ${MPI_LIBRARIES} dl m rt)
SET_TARGET_PROPERTIES(
    aes_mpi
    PROPERTIES
    COMPILE_FLAGS "-I/usr/lib/openmpi/include/openmpi -I/usr/lib/openmpi/include -pthread"
    LINK_FLAGS "-L/usr/lib/openmpi/lib -lmpi -lopen-rte -lopen-pal -ldl -Wl,--export-dynamic -lnsl -lutil -lm -ldl -lrt"
)

ADD_LIBRARY(hash_md5 SHARED hash_md5.c md5.c)

install(
    TARGETS aes_ctr aes_test hash_md5 aes_mpi
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

install(
    PROGRAMS test_thread.sh test_mpi.sh ping.sh
    DESTINATION bin
)


