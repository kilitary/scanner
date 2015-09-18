This document contains instructions for using the IPWorksSSH toolkit with Qt.

The "qt" folder in the toolkit installation location contains a set of headers for use when creating Qt applications. 
This directory also contains a makefile.

First run the makefile with the make command. 
If you are on Windows you can use NMAKE (http://msdn.microsoft.com/en-us/library/dd9y37ha(VS.80).aspx) to do this. 
NMAKE ships with Microsoft Visual Studio and can be used from the Visual Studio Command Prompt.
For example:

NMAKE makefile

NOTE: Depending on the location of your Qt installation you may need to edit this line in the makefile:

MOC=C:\Qt\4.6.2\bin\moc.exe

Running the makefile will create a set of cpp files in the "qt" folder that have the format "ComponentName_moc.cpp".

Once this is complete you are ready to begin using the components in the Qt Creator IDE or from the Qt Visual Studio plugin.


Instructions for using the components in the Qt Creator IDE:

1) In your Qt project first add the appropriate #include statement in your source file to include the .h file(s) from the "qt" folder.

2) Edit the .pro file to link to the .lib file. For instance:

win32:LIBS += "C:\\Program Files\\nsoftware\\[Product Name] C++ Edition\\lib\\[Product Name].lib"

3) Right click on the "Sources" folder in the project explorer and choose "Add Existing Files...". 
Browse to the "qt" folder and add the "ComponentName_moc.cpp" files.

4) Edit the .pro file and verify that the paths to the *.moc files listed under SOURCES are in quotes. 
These paths must be in quotes if the path contains spaces.

Your application can now be built and run using the components.


Instructions for using the components with the Visual Studio Add-In

1) After creating a new Qt project first add the appropriate #include statement in your source file to include the .h file(s) from the "qt" folder.

2) You will need to update the input files for the linker to link against the correct .lib file. To do this go to:

Project -> Properties -> Configuration Properties -> Linker -> Input -> Additional Dependencies

And add the path:

"C:\\Program Files\\nsoftware\\[Product Name] C++ Edition\\lib\\[Product Name].lib"

Be sure to surround this value with quotes if the path name contains spaces.

3) Right click on the "Source Files" folder in the solution explorer and choose Add -> Existing Item. 
Browse to the "qt" folder and add the "ComponentName_moc.cpp" files.