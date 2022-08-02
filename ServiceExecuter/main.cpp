#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iostream>
#include <thread>
#include <iostream>
#include <fstream>
#include <cstdio>

#define SE_CREATE_SYMBOLIC_LINK		35

const int MsToSleepBetweenCommands = 200; // miliseconds 

int readFile(std::string pathInput, std::string* output)
{
	std::fstream newfile;
	newfile.open(pathInput, std::ios::in); //open a file to perform read operation using file object
	if (newfile.is_open()) 
	{ 
		std::string tp;
		std::getline(newfile, tp); //read data from file object and put it into string.
		*output += tp;
		newfile.close(); //close the file object.
	}
	else 
	{
		return -1;
	}

	return 0;
}

int writeFile(std::string pathOutput, std::string* contentToWrite)
{
	std::fstream newfile;
	newfile.open(pathOutput, std::ios::out);  // open a file to perform write operation using file object
	if (newfile.is_open()) //checking whether the file is open
	{
		newfile << contentToWrite; //inserting text
	}
	else 
	{
		return -1;
	}
	newfile.close(); //close the file object

	return 0;
}

void deleteFile(std::string pathFile) 
{
	std::remove(pathFile.c_str());
}

int executeCommand(std::string command, std::string outputPath) 
{
	std::string concatString = command + " > " + outputPath;
	std::cout << "Executing command: '" << concatString << "'\n";
	return system(concatString.c_str());	
}


int main(int argc, char* argv[])
{
	int ret_val = 0;
	// argv[1] - input command
	// argv[2] - output command 
	if (argc < 3) 
	{
		std::cout << "Wrong arguments" << std::endl << "Usage: " << argv[0] << " <Path input command> <Path output command>" << std::endl;
		return -1;
	}
	std::string pathInputCommand = std::string(argv[1]);
	std::string pathOutputCommand = std::string(argv[2]);
	while (true) 
	{
		std::string command;
		int ret_val = readFile(pathInputCommand, &command);
		if (0 != ret_val) 
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(MsToSleepBetweenCommands));
			continue;
		}
		deleteFile(pathInputCommand);
		executeCommand(command, pathOutputCommand);

	}
	printf("\n");

	if (0 == ret_val)
	{
		printf("SUCCESS %d \n", ret_val);
	}
	else
	{
		printf("FAILED %d \n", ret_val);
	}

	return ret_val;
}