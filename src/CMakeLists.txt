# Create a variable containing all .cpp files
FILE(GLOB files *.cpp)

# Create an executable file from sources
ADD_EXECUTABLE(aes_ctr ${files})

install(
  TARGETS aes_ctr
  RUNTIME DESTINATION bin
)
