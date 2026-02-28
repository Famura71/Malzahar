# CMakeList.txt : CMake project for Malzahar, include source and define
# project specific logic here.
#

# Add source to this project's executable.
if (WIN32)
  add_executable(Malzahar Malzahar.cpp app_icon.rc)
else()
  add_executable(Malzahar Malzahar.cpp)
endif()

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Malzahar PROPERTY CXX_STANDARD 20)
endif()

target_link_libraries(Malzahar PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# TODO: Add tests and install targets if needed.
