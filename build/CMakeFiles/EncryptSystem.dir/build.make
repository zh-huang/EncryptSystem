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
include CMakeFiles/EncryptSystem.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/EncryptSystem.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/EncryptSystem.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/EncryptSystem.dir/flags.make

CMakeFiles/EncryptSystem.dir/main.cpp.o: CMakeFiles/EncryptSystem.dir/flags.make
CMakeFiles/EncryptSystem.dir/main.cpp.o: ../main.cpp
CMakeFiles/EncryptSystem.dir/main.cpp.o: CMakeFiles/EncryptSystem.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/EncryptSystem.dir/main.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptSystem.dir/main.cpp.o -MF CMakeFiles/EncryptSystem.dir/main.cpp.o.d -o CMakeFiles/EncryptSystem.dir/main.cpp.o -c /home/hzh/Documents/EncryptSystem/main.cpp

CMakeFiles/EncryptSystem.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EncryptSystem.dir/main.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/main.cpp > CMakeFiles/EncryptSystem.dir/main.cpp.i

CMakeFiles/EncryptSystem.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EncryptSystem.dir/main.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/main.cpp -o CMakeFiles/EncryptSystem.dir/main.cpp.s

CMakeFiles/EncryptSystem.dir/common.cpp.o: CMakeFiles/EncryptSystem.dir/flags.make
CMakeFiles/EncryptSystem.dir/common.cpp.o: ../common.cpp
CMakeFiles/EncryptSystem.dir/common.cpp.o: CMakeFiles/EncryptSystem.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/EncryptSystem.dir/common.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptSystem.dir/common.cpp.o -MF CMakeFiles/EncryptSystem.dir/common.cpp.o.d -o CMakeFiles/EncryptSystem.dir/common.cpp.o -c /home/hzh/Documents/EncryptSystem/common.cpp

CMakeFiles/EncryptSystem.dir/common.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EncryptSystem.dir/common.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/common.cpp > CMakeFiles/EncryptSystem.dir/common.cpp.i

CMakeFiles/EncryptSystem.dir/common.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EncryptSystem.dir/common.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/common.cpp -o CMakeFiles/EncryptSystem.dir/common.cpp.s

CMakeFiles/EncryptSystem.dir/crypt.cpp.o: CMakeFiles/EncryptSystem.dir/flags.make
CMakeFiles/EncryptSystem.dir/crypt.cpp.o: ../crypt.cpp
CMakeFiles/EncryptSystem.dir/crypt.cpp.o: CMakeFiles/EncryptSystem.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/EncryptSystem.dir/crypt.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptSystem.dir/crypt.cpp.o -MF CMakeFiles/EncryptSystem.dir/crypt.cpp.o.d -o CMakeFiles/EncryptSystem.dir/crypt.cpp.o -c /home/hzh/Documents/EncryptSystem/crypt.cpp

CMakeFiles/EncryptSystem.dir/crypt.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EncryptSystem.dir/crypt.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/crypt.cpp > CMakeFiles/EncryptSystem.dir/crypt.cpp.i

CMakeFiles/EncryptSystem.dir/crypt.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EncryptSystem.dir/crypt.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/crypt.cpp -o CMakeFiles/EncryptSystem.dir/crypt.cpp.s

CMakeFiles/EncryptSystem.dir/keygen.cpp.o: CMakeFiles/EncryptSystem.dir/flags.make
CMakeFiles/EncryptSystem.dir/keygen.cpp.o: ../keygen.cpp
CMakeFiles/EncryptSystem.dir/keygen.cpp.o: CMakeFiles/EncryptSystem.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/EncryptSystem.dir/keygen.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptSystem.dir/keygen.cpp.o -MF CMakeFiles/EncryptSystem.dir/keygen.cpp.o.d -o CMakeFiles/EncryptSystem.dir/keygen.cpp.o -c /home/hzh/Documents/EncryptSystem/keygen.cpp

CMakeFiles/EncryptSystem.dir/keygen.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EncryptSystem.dir/keygen.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/keygen.cpp > CMakeFiles/EncryptSystem.dir/keygen.cpp.i

CMakeFiles/EncryptSystem.dir/keygen.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EncryptSystem.dir/keygen.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/keygen.cpp -o CMakeFiles/EncryptSystem.dir/keygen.cpp.s

CMakeFiles/EncryptSystem.dir/sign.cpp.o: CMakeFiles/EncryptSystem.dir/flags.make
CMakeFiles/EncryptSystem.dir/sign.cpp.o: ../sign.cpp
CMakeFiles/EncryptSystem.dir/sign.cpp.o: CMakeFiles/EncryptSystem.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/EncryptSystem.dir/sign.cpp.o"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptSystem.dir/sign.cpp.o -MF CMakeFiles/EncryptSystem.dir/sign.cpp.o.d -o CMakeFiles/EncryptSystem.dir/sign.cpp.o -c /home/hzh/Documents/EncryptSystem/sign.cpp

CMakeFiles/EncryptSystem.dir/sign.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EncryptSystem.dir/sign.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hzh/Documents/EncryptSystem/sign.cpp > CMakeFiles/EncryptSystem.dir/sign.cpp.i

CMakeFiles/EncryptSystem.dir/sign.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EncryptSystem.dir/sign.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hzh/Documents/EncryptSystem/sign.cpp -o CMakeFiles/EncryptSystem.dir/sign.cpp.s

# Object files for target EncryptSystem
EncryptSystem_OBJECTS = \
"CMakeFiles/EncryptSystem.dir/main.cpp.o" \
"CMakeFiles/EncryptSystem.dir/common.cpp.o" \
"CMakeFiles/EncryptSystem.dir/crypt.cpp.o" \
"CMakeFiles/EncryptSystem.dir/keygen.cpp.o" \
"CMakeFiles/EncryptSystem.dir/sign.cpp.o"

# External object files for target EncryptSystem
EncryptSystem_EXTERNAL_OBJECTS =

EncryptSystem: CMakeFiles/EncryptSystem.dir/main.cpp.o
EncryptSystem: CMakeFiles/EncryptSystem.dir/common.cpp.o
EncryptSystem: CMakeFiles/EncryptSystem.dir/crypt.cpp.o
EncryptSystem: CMakeFiles/EncryptSystem.dir/keygen.cpp.o
EncryptSystem: CMakeFiles/EncryptSystem.dir/sign.cpp.o
EncryptSystem: CMakeFiles/EncryptSystem.dir/build.make
EncryptSystem: CMakeFiles/EncryptSystem.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/hzh/Documents/EncryptSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable EncryptSystem"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/EncryptSystem.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/EncryptSystem.dir/build: EncryptSystem
.PHONY : CMakeFiles/EncryptSystem.dir/build

CMakeFiles/EncryptSystem.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/EncryptSystem.dir/cmake_clean.cmake
.PHONY : CMakeFiles/EncryptSystem.dir/clean

CMakeFiles/EncryptSystem.dir/depend:
	cd /home/hzh/Documents/EncryptSystem/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hzh/Documents/EncryptSystem /home/hzh/Documents/EncryptSystem /home/hzh/Documents/EncryptSystem/build /home/hzh/Documents/EncryptSystem/build /home/hzh/Documents/EncryptSystem/build/CMakeFiles/EncryptSystem.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/EncryptSystem.dir/depend

