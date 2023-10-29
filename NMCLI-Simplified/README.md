# NetworkManager Command Line Interface (nmcli) Simplified
### (Created by TheAnonymousCrusher on Github)

The following article provides a simple documentation for the
nmcli aliases used to simplify the process of managing network
connections in a Linux system. 
<br><br>
It also highlights that ```nmcli``` works well with window managers like ```sway``` or ```dwm```, which typically have no UI to connect to networks. This makes ```nmcli``` an essential tool for these environments, despite the inefficiency of its syntax. This project aims to address this issue by improving the syntax and overall user experience for regular nmcli users.

# Basic Use
## 1. Connect to a Network

The nmcon alias is used to connect to a WiFi network.The
command requires the name of the WiFi network and the password
as arguments. The syntax is as follows:

```nmcon 'WIFI_NAME' password 'PASSWORD'```

For example, to connect to a WiFi network named 'Office_Wifi'
with the password 'password1234', you would use:

```nmcon 'Office_Wifi' password 'password1234'```

## 2. Disconnect from a Network

The nmdis alias is used to disconnect from a WiFi network. The
command requires the name of the WiFi network as an argument.
The syntax is as follows:

```nmdis 'WIFI_NAME'```

For example, to disconnect from a WiFi network named
'Office_Wifi', you would use:

```nmdis 'Office_Wifi'```

## 3. Show Network Status

The nmstat alias is used to display the status of all the
network devices. The command does not require any arguments.
The syntax is as follows:

```nmstat```

## 4. Show Network List

The nmlist alias is used to display a list of all the network
connections that have been established. The command does not
require any arguments. The syntax is as follows:

```nmlist```

## Conclusion

Please note that these aliases are simplified versions of
nmcli commands and are intended to make the process of managing
network connections easier and more intuitive for users.

# Installation

## Full Installation in a Single Command
To fully set up and install NMCLI-Simplified, execute the following command:

```sh
git clone https://github.com/TheAnonymousCrusher/NMCLI-Simplified.git
cd NMCLI-Simplified
chmod u+x setup.sh
./setup.sh
```
## Step-by-Step Installation

If you prefer to go through the installation process step-by-step, please follow the instructions below:

### Step 1: Cloning the Repository
Execute the following command to clone this project from the Github repository:<br>
```git clone https://github.com/TheAnonymousCrusher/NMCLI-Simplified.git```


### Step 2: Changing to the Project Directory
Next, navigate to the directory into which the project has been cloned. You can do this by running the following command:<br>
```cd NMCLI-Simplified```


### Step 3: Modifying the Script Permissions
After navigating to the correct directory, the next step is to modify the permissions of the .sh file to make it executable. This can be achieved by running the following command:<br>
```chmod u+x setup.sh```

### Step 4: Running the Installation Script
Finally, execute the installation script to begin the installation process. This can be done by running the following command:<br>
```./setup.sh```

# Final Note

This project has been meticulously developed, and it would be greatly appreciated if you could express your support through a  ❤️<br>
Lastly, I sincerely hope that you have find the experience of using *NMCLI Simplified* convenient.
