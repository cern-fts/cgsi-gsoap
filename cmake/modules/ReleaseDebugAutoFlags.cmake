## debug / release autoManagement



set(CMAKE_C_FLAGS_RELEASE  "-O2")
set(CMAKE_C_FLAGS_DEBUG  "-g -Wall -fstack-protector-all")


set(CMAKE_CXX_FLAGS_RELEASE  "-O2")
set(CMAKE_CXX_FLAGS_DEBUG  "-g -Wall -fstack-protector-all")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -Wall")
