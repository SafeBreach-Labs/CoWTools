# LiveDump 
Live dump of the kernel and usermode. 

# Dumping inside Windows container 
It is possible to dump the kernel of the host.
It is not possible to dump usermode processes outside of the container.

# How to execute 
LiveDump.exe kernel -c -d -h <path_to_dump_kernel_inside_the_container.dmp>

if kernel debugger is enabled and attached - it is possible to do a live dump of the usermode as well 
If it is inside the container - it will dump all the processes inside the container and outside of the container.
LiveDump.exe kernel -c -d -h -u <path_to_dump_kernel_inside_the_container.dmp>

# Source 
This project is based on the following repos (few changes were made in order to support the changes since 2014)
https://code.google.com/archive/p/livedump/
License: GNU GPL v3

Blogposts written relates to this repo:
https://crashdmp.wordpress.com/2014/08/04/livedump-1-0-is-available/
https://crashdmp.wordpress.com/2014/08/01/introducing-livedump-exe/
