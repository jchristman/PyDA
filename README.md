PyDA
====

The Python DisAssembler is a disassembler built on the Capstone Engine that aims to provide an easy front end to disassembling many file formats and architectures. It is written in pure Python and has the Capstone Engine as its only non-native dependency.

The Capstone Engine can be found at http://www.capstone-engine.org/. In order to make this program work, you must visit http://www.capstone-engine.org/download.html and download the appropriate libraries. If you are on windows, just install the "Python module for Windows XX - Binaries" and you're good to go. For other operating systems, follow the steps at http://www.capstone-engine.org/documentation.html to install the engine and python bindings. It's fairly straightforward and easy to do.

The purpose of this program is to provide an easy to use disassembler that supports many file types. It abstracts disassembly functionality out to individual, format-specific modules that are located in the disassembler/formats directory. The individual modules must only behave in a certain way and put their disassembly into the CommonExecutableDisassemblyFormat data structures located in formats/disassembly/helpers.py in order for them to be accepted into the program. This would allow anyone to design a module that disassembles a single executable format and dump it into that directory and, without any changes to the code, have it automatically imported into PyDA. elf.py is the example of how to write the modules and is the first (and only for now) supported executable format in PyDA.

The program is written in such a way as to require a minimal amount of dependencies from pure Python. Therefore, Tkinter was chosen as the GUI library as it is installed by default with Python and makes cross platform implementation simplest. The only dependency is the capstone library which is linked above for your convenience. I will keep as up to date with the capstone API as possible, but right now the API is 2.1.1.
