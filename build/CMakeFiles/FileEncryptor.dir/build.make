# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/hzh/Documents/EncryptSystem

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hzh/Documents/EncryptSystem/build

# Include any dependencies generated for this target.
include CMakeFiles/FileEncryptor.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/FileEncryptor.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/FileEncryptor.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/FileEncryptor.dir/flags.make

CMakeFiles/FileEncryptor.dir/main.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/main.cpp.o: ../main.cpp
CMakeFiles/FileEncryptor.dir/main.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/FileEncryptor.dir/main.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/main.cpp.o -MF CMakeFiles/FileEncryptor.dir/main.cpp.o.d -o CMakeFiles/FileEncryptor.dir/main.cpp.o -c /home/hzh/Documents/EncryptSystem/main.cpp

CMakeFiles/FileEncryptor.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/main.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/main.cpp > CMakeFiles/FileEncryptor.dir/main.cpp.i

CMakeFiles/FileEncryptor.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/main.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/main.cpp -o CMakeFiles/FileEncryptor.dir/main.cpp.s

CMakeFiles/FileEncryptor.dir/common.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/common.cpp.o: ../common.cpp
CMakeFiles/FileEncryptor.dir/common.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/FileEncryptor.dir/common.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/common.cpp.o -MF CMakeFiles/FileEncryptor.dir/common.cpp.o.d -o CMakeFiles/FileEncryptor.dir/common.cpp.o -c /home/hzh/Documents/EncryptSystem/common.cpp

CMakeFiles/FileEncryptor.dir/common.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/common.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/common.cpp > CMakeFiles/FileEncryptor.dir/common.cpp.i

CMakeFiles/FileEncryptor.dir/common.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/common.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/common.cpp -o CMakeFiles/FileEncryptor.dir/common.cpp.s

CMakeFiles/FileEncryptor.dir/decrypt.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/decrypt.cpp.o: ../decrypt.cpp
CMakeFiles/FileEncryptor.dir/decrypt.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/FileEncryptor.dir/decrypt.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/decrypt.cpp.o -MF CMakeFiles/FileEncryptor.dir/decrypt.cpp.o.d -o CMakeFiles/FileEncryptor.dir/decrypt.cpp.o -c /home/hzh/Documents/EncryptSystem/decrypt.cpp

CMakeFiles/FileEncryptor.dir/decrypt.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/decrypt.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/decrypt.cpp > CMakeFiles/FileEncryptor.dir/decrypt.cpp.i

CMakeFiles/FileEncryptor.dir/decrypt.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/decrypt.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/decrypt.cpp -o CMakeFiles/FileEncryptor.dir/decrypt.cpp.s

CMakeFiles/FileEncryptor.dir/encrypt.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/encrypt.cpp.o: ../encrypt.cpp
CMakeFiles/FileEncryptor.dir/encrypt.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/FileEncryptor.dir/encrypt.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/encrypt.cpp.o -MF CMakeFiles/FileEncryptor.dir/encrypt.cpp.o.d -o CMakeFiles/FileEncryptor.dir/encrypt.cpp.o -c /home/hzh/Documents/EncryptSystem/encrypt.cpp

CMakeFiles/FileEncryptor.dir/encrypt.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/encrypt.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/encrypt.cpp > CMakeFiles/FileEncryptor.dir/encrypt.cpp.i

CMakeFiles/FileEncryptor.dir/encrypt.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/encrypt.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/encrypt.cpp -o CMakeFiles/FileEncryptor.dir/encrypt.cpp.s

CMakeFiles/FileEncryptor.dir/keygen.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/keygen.cpp.o: ../keygen.cpp
CMakeFiles/FileEncryptor.dir/keygen.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/FileEncryptor.dir/keygen.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/keygen.cpp.o -MF CMakeFiles/FileEncryptor.dir/keygen.cpp.o.d -o CMakeFiles/FileEncryptor.dir/keygen.cpp.o -c /home/hzh/Documents/EncryptSystem/keygen.cpp

CMakeFiles/FileEncryptor.dir/keygen.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/keygen.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/keygen.cpp > CMakeFiles/FileEncryptor.dir/keygen.cpp.i

CMakeFiles/FileEncryptor.dir/keygen.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/keygen.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/keygen.cpp -o CMakeFiles/FileEncryptor.dir/keygen.cpp.s

CMakeFiles/FileEncryptor.dir/sign.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/sign.cpp.o: ../sign.cpp
CMakeFiles/FileEncryptor.dir/sign.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/FileEncryptor.dir/sign.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/sign.cpp.o -MF CMakeFiles/FileEncryptor.dir/sign.cpp.o.d -o CMakeFiles/FileEncryptor.dir/sign.cpp.o -c /home/hzh/Documents/EncryptSystem/sign.cpp

CMakeFiles/FileEncryptor.dir/sign.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/sign.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/sign.cpp > CMakeFiles/FileEncryptor.dir/sign.cpp.i

CMakeFiles/FileEncryptor.dir/sign.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/sign.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/sign.cpp -o CMakeFiles/FileEncryptor.dir/sign.cpp.s

CMakeFiles/FileEncryptor.dir/verify.cpp.o: CMakeFiles/FileEncryptor.dir/flags.make
CMakeFiles/FileEncryptor.dir/verify.cpp.o: ../verify.cpp
CMakeFiles/FileEncryptor.dir/verify.cpp.o: CMakeFiles/FileEncryptor.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/FileEncryptor.dir/verify.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FileEncryptor.dir/verify.cpp.o -MF CMakeFiles/FileEncryptor.dir/verify.cpp.o.d -o CMakeFiles/FileEncryptor.dir/verify.cpp.o -c /home/hzh/Documents/EncryptSystem/verify.cpp

CMakeFiles/FileEncryptor.dir/verify.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/FileEncryptor.dir/verify.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/verify.cpp > CMakeFiles/FileEncryptor.dir/verify.cpp.i

CMakeFiles/FileEncryptor.dir/verify.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/FileEncryptor.dir/verify.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/verify.cpp -o CMakeFiles/FileEncryptor.dir/verify.cpp.s

# Object files for target FileEncryptor
FileEncryptor_OBJECTS = \
"CMakeFiles/FileEncryptor.dir/main.cpp.o" \
"CMakeFiles/FileEncryptor.dir/common.cpp.o" \
"CMakeFiles/FileEncryptor.dir/decrypt.cpp.o" \
"CMakeFiles/FileEncryptor.dir/encrypt.cpp.o" \
"CMakeFiles/FileEncryptor.dir/keygen.cpp.o" \
"CMakeFiles/FileEncryptor.dir/sign.cpp.o" \
"CMakeFiles/FileEncryptor.dir/verify.cpp.o"

# External object files for target FileEncryptor
FileEncryptor_EXTERNAL_OBJECTS =

FileEncryptor: CMakeFiles/FileEncryptor.dir/main.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/common.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/decrypt.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/encrypt.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/keygen.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/sign.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/verify.cpp.o
FileEncryptor: CMakeFiles/FileEncryptor.dir/build.make
FileEncryptor: CMakeFiles/FileEncryptor.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking CXX executable FileEncryptor"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/FileEncryptor.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/FileEncryptor.dir/build: FileEncryptor
.PHONY : CMakeFiles/FileEncryptor.dir/build

CMakeFiles/FileEncryptor.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/FileEncryptor.dir/cmake_clean.cmake
.PHONY : CMakeFiles/FileEncryptor.dir/clean

CMakeFiles/FileEncryptor.dir/depend:
	cd /home/hzh/Documents/EncryptSystem/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hzh/Documents/EncryptSystem /home/hzh/Documents/EncryptSystem /home/hzh/Documents/EncryptSystem/build /home/hzh/Documents/EncryptSystem/build /home/hzh/Documents/EncryptSystem/build/CMakeFiles/FileEncryptor.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/FileEncryptor.dir/depend

