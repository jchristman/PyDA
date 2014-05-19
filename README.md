PyDA
====

This program is currently in alpha and in heavy development mode (on our free time), so expect unstable behaviors as we develop. We currently have a "stable" master (that is slightly useable) and all current work will be done on the "unstable" branch. If you want to checkout that branch, it will have more current developments included, but it might not work as well as we rework data structures, add new functionality, test new features, etc. On that nore, below is a description of the project.

The Python DisAssembler is a disassembler built on the Capstone Engine that aims to provide an easy front end to disassembling many file formats and architectures. It is written in pure Python and has the Capstone Engine as its only non-native dependency.

The Capstone Engine can be found at http://www.capstone-engine.org/. In order to make this program work, you must visit http://www.capstone-engine.org/download.html and download the appropriate libraries. If you are on windows, just install the "Python module for Windows XX - Binaries" and you're good to go. For other operating systems, follow the steps at http://www.capstone-engine.org/documentation.html to install the engine and python bindings. It's fairly straightforward and easy to do.

The purpose of this program is to provide an easy to use disassembler that supports many file types. It abstracts disassembly functionality out to individual, format-specific modules that are located in the disassembler/formats directory. The individual modules must only behave in a certain way and put their disassembly into a data structure in order for them to be accepted into the program. This would allow anyone to design a module that disassembles a single executable format, putting it into that directory and, without any changes to the code, have it automatically imported into PyDA. See the current modules for an example of how to write the modules.

The program is written in such a way as to require a minimal amount of dependencies from pure Python. Therefore, Tkinter was chosen as the GUI library as it is installed by default with Python and makes cross platform implementation simplest. The only dependency is the capstone library which is linked above for your convenience. I will keep as up to date with the capstone API as possible, but right now the API is 2.1.1.

Donations
=========
If you like this project and want to donate:
BTC: 1CYP9apFMB2DgCbRxo1oAJNsbMwKbe6QyV
DOGE: D8ra8gDYqK4Mx52Q5nw5GjA9nDRjNJpzee
