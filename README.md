# WSL2 installer
This script installs Windows Subsystem for Linux (WSL 2) on a Windows computer (even with no Microsoft Store access) with optional X Server and audio (Pulse audio is currently not working :( )

## Introduction
If you are using a VMWare or VirtualBox or Hyper-V for working with Linux based tools, WSL gives you a great alternative. Read on here: https://docs.microsoft.com/en-us/windows/wsl/about

## What the script does
As you can see below, installing WSL2, so that it works, even with X-Windows Server and audio, is not straightforward. This script guides you trough the process, enables Windows components, sets settings, downloads and intall third party software.

## How to use the script
This is a Windows Powershell script and requires admin rights and Internet connection to run.
1. Open a PowerShell window with admin rights
2. Navigate to the script's location (use the "cd <script_location>" command)
3. Start the script (./wsl2i.ps) and follow the instructions

## How to customize basic settings
The script supports the following parameters:
- pulse_path [string]: Specifies where to install/search for Pulse Audio Server if you opt-in for using it. Set this parameter, if you want to install/use Pulse Audio to/from a specific location. The default value is `$env:ProgramFiles\Pulse`.
- firewall_rule_name [string]: Specifies what should be the name of the firewall rule. Firewall rule is only created if X-Windows server and/or Pulse Audio server is enabled. Use this variable, if you want to change the default value. The default value is `WSL Server`.
- distro [string]: used to find the distro local, then if it is not available in the online distribution source from Microsoft (wsl -l -o).

Examples:
```
./wsl2i.ps1 -pulse_path "d:\wsl\pulse" -firewall_rule_name "_for_wsl" 

./wsl2i.ps1 -distro "Debian"

```

## How to customize advanced settings
The script can be taylored using the variables at the top of the script. If you modify a variable, please check for the usages as well to make sure the change will not break the script. 

## How to ccess files WSL2<->Windows

WSL2's (virtual)drive is shared as \\wsl$\<distro name> like \\wsl$\Ubuntu-20.04

Windows drives are mounted in WSL under /mnt, like /mnt/c/Users == c:\Users


# Step-by step guide for manual setup of WSL 2

## Install WSL22

0. Check if your installation supports WSL2: Windows logo key + R, type winver [enter]. You should have Version 1903 or higher, with Build 18362 or higher

1. Enable WSL2
    1. Open an admin prompt (Press shift+ctrl and click on PowerShell/cmd)
    2. dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    3. Reboot your computer
    4. Download and install the WSL2 kernel from: https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi
    5. Open a PowerShell or cmd and execute:
        ```
	wsl --set-default-version 2
	```
    6. Update the kernel
        ```
        wsl --update
	```
	
2. Install a Linux distro - modern way
    1. List available distros
       ```
       wsl -l -o
       ```
    2. Install the one you want to have
       ```
       wsl --install -d <name>
       ```
   Install a Linux distro - legacy way    
       
    1. Please **only download** an available distro from here: https://docs.microsoft.com/en-us/windows/wsl/install-manual
        Explanation: if you install through appx installer without Windows Store enabled, you might run into a 'File not found' or 0x80070002 error.
    2. Create a location on your system drive (see: https://docs.microsoft.com/en-us/windows/wsl/install-win10#troubleshooting-installation, but it works for me on D: drive) where you want your distro to run from (like c:\work\wsl)
    3. Extract the downloaded distro appx file using your favorite zip tool (7Zip or WinZip or ..) into the selected location (Right click on the appx and extract to the created folder (like c:\work\wsl))
    4. Set access rights for your Linux installer folder so that everybody has all the rights
        Open a cmd or PowerShell and execute: icacls [your folder] /t /grant Everyone:(OI)(CI)F 
        Example: icacls c:\work\wsl /t /grant Everyone:(OI)(CI)F
    5. Start the setup as Administrator. Example with Ubuntu: right click on ubuntu2004.exe and select Run as adminsitrator
    6. Follow the on screen instructions

3. Test your WSL2
    1. After the setup finished and you have the Linux command prompt try to start bash from Windows' Run (Win+R)
    2. Exit from the started bash and from the bash you got after the installation
    3. Start bash from Windows' Run (Win+R) (again)

You should have a working WSL2. If not, let me know.


## Fix DNS issue (https://gist.github.com/coltenkrauter/608cfe02319ce60facd76373249b8ca6)

If you execute ping google.com in WSL2, and the result is 'Temporary error in name resolution' try this:

0. Start the environment
    1. open windows cmd or PowerShell
    2. start bash (type: bash and then press enter)

1. Disable automatic generation of `resolv.conf`
    1. cd /etc
    2. echo "[network]" | sudo tee wsl.conf # Create wsl.conf file and add a [network] section
    3. echo "generateResolvConf = false" | sudo tee -a wsl.conf # Append wsl.conf a setting to disable generation of resolv.conf

2. Shutdown WSL
    1. To exit WSL and go back to cmd/PowerShell type: exit
    2. To terminate WSL type: wsl --shutdown

3. The two simplest solution to pick DNS server address: 

 **a. Use the one configured for Windows**
 
  - In windows cmd type ipconfig /all for get all the data about your Windows IP network, including the primary and secondary DNS server address. Sometimes there is only one DNL Server listed. Example:
```
           Default Gateway . . . . . . . . . : 192.168.1.1
           DHCPv4 Class ID . . . . . . . . . : ra006
           DHCP Server . . . . . . . . . . . : 192.168.1.1
        ==>DNS Servers . . . . . . . . . . . : 192.168.1.1<== look for this line
           NetBIOS over Tcpip. . . . . . . . : Disabled
```

   - Alternatively you can use this hacky PowerShell snippet:
	     
```
((Get-NetIPConfiguration |
                Where-Object {
                    $_.IPv4DefaultGateway -ne $null -and
                    $_.NetAdapter.Status -ne "Disconnected"
                }
            ).DNSServer | 
                Where-Object {
                    $_.AddressFamily -eq 2
                }
            ).ServerAddresses
```
 **b. Use Google's Public DNS IP addresses**
   - use the value: 8.8.8.8
   
4. Configure the DNS Server in WSL
    1. bash
    2. cd /etc
    3. sudo rm -Rf resolv.conf # Delete the resolv.conf file, which is a simlink actually, you can use unlink if you prefer
    4. echo "nameserver X.X.X.X" | sudo tee resolv.conf # REPLACE the X.X.X.X with the primary DNS you have determined above
    5. echo "nameserver Y.Y.Y.Y" | sudo tee -a resolv.conf  # REPLACE the Y.Y.Y.Y with the secondary DNS you have determined above. If you don't have a secondary DNS, skip this!
    6. sudo chattr +i resolv.conf # make it immutable (unchangeable)

5. Restart WSL
    1. exit
    2. wsl --shutdown
    3. bash

6. ping google.com

The DNS should be functional

+1. You might need one more additional step: replace the REPLACE_Your_Network_Interface_Name_REPLACE with your Network Interface's name.
    Get-NetAdapter | Where-Object {$_.InterfaceDescription -Match "REPLACE_Your_Network_Interface_Name_REPLACE"} | Set-NetIPInterface -InterfaceMetric 6000

## Renaming a WSL instance

This involves registry editing, please read: https://superuser.com/questions/1507237/how-to-change-the-name-of-a-wsl-distro-to-reflect-the-actual-distro

## Using XWindows with WSL2 

Unlike WSL, WSL2 runs in a small hyper-v image. Therefore the network communication is not that trivial and it was in WSL.
To have a XWindows (and pulse audio) we need to setup the 'servers' on the Windows side, then configure the Linux side then setup a firewall rule so that they can communicate.

1. Download and install VcXsrv from https://sourceforge.net/projects/vcxsrv/

1. For (auto)start with Windows: 
    1. open %appdata%\Microsoft\Windows\Start Menu\Programs\Startup
    2. create a new shortcut (right click, new, shortcut)
    3. copy and paste: "C:\Program Files\VcXsrv\vcxsrv.exe" :0 -ac -terminate -lesspointer -multiwindow -clipboard -nowgl
      - Fix the C:\Program Files\VcXsrv\ path to your installation if needed.
      - The ac flag is needed, because the XSrv will be accesses from a different computer (WSL2 runs in Hyper-V)
      - Why nowgl? Usually the articles say to enable native opengl, but this setting didn't work for me. If you have low performance on opengl, try using -wgl (see also LIBGL_ALWAYS_INDIRECT below).
      - The above settings (more-or-less) on XLaunch: multiple windows, display 0, start no client, enable clipboard, disable native opengl, enable access control

1. Start VcXsrv (either through the created shortcut, or with XLaunch from the Start Menu)

1. In your Linux distro you need to export the DISPLAY variable. The below line will automatically use the correct IP, even though your IP is changed (use `source ~\.bashrc` to update the setting on a long running bash)
   ```
   echo 'export DISPLAY=$(route.exe print | grep 0.0.0.0 | head -1 | awk '\''{print $4;}'\''):0' >> ~/.bashrc
   ```

1. You need to set an inbound firewall rule, so that VcXsrv can receive the XWindows communication
    1. To start Windows Firewall Settings type: wf.msc
    2. Click: Inbound Rules
    3. Click: New Rule (either on the right side pane or right-click Inbound Rules)
      1. Select: Custom, 
      2. Select: All programs
      3. Select: Any protocol
      4. Both in local and remote IP box add your IP address you determined above
      5. Allow the connection
      6. Select: Domain and Private, decelect Public
      7. Name as WSL Server

1. Test from Linux:
	1. sudo apt install mesa-utils
	2. glxgears
	
1. Legacy notes:

* Get your IP address
    1. Open a PowerShell or cmd
    2. Type: ipconfig /all
    3. Locate the network adapter, where the DNS server setting is available (same as in the fix for the DNS server issue):
    [...]
    Ethernet adapter something (NiceNameForSomething):
```
       Connection-specific DNS Suffix  . :
       Description . . . . . . . . . . . : Description here!
       Physical Address. . . . . . . . . : FF-00-FF-00-FF-00
       DHCP Enabled. . . . . . . . . . . : Yes
       Autoconfiguration Enabled . . . . : Yes
    ==>IPv4 Address. . . . . . . . . . . : 192.168.1.111(Preferred)<== this is what you need
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Lease Obtained. . . . . . . . . . : Friday, March 26, 2021 09:16:34
       Lease Expires . . . . . . . . . . : Friday, March 26, 2021 11:28:41
       Default Gateway . . . . . . . . . : 192.168.1.1
       DHCPv4 Class ID . . . . . . . . . : ra006
       DHCP Server . . . . . . . . . . . : 192.168.1.1
       DNS Servers . . . . . . . . . . . : 192.168.1.1
       NetBIOS over Tcpip. . . . . . . . : Disabled
    [...]
```

    In this example your IP address is 192.168.1.111

    Alternatively you can use this hacky PowerShell snippet:
```
(Get-NetIPConfiguration |
	    Where-Object {
		$_.IPv4DefaultGateway -ne $null -and
		$_.NetAdapter.Status -ne "Disconnected"
	    }
	).IPv4Address.IPAddress    
```

* In your Linux distro you need to export the DISPLAY variable (REPLACE 192.168.1.111 with your IP address)
    1. To start Linux type: bash
    2. echo "export DISPLAY=192.168.1.111:0" >> ~/.bashrc
    3. source ~/.bashrc

    If your IP address changes, you will need to update the export for DISPLAY.
    If you have issues with opengl, try enabling wgl for the VcXsrv (see above), and export LIBGL_ALWAYS_INDIRECT=1 in ~/.bashrc

## Audio with WSL2 (https://tomjepp.uk/2015/05/31/streaming-audio-from-linux-to-windows.html)

Similarly to XWindows communication, the WSL2 Pulse server will use the firewall rule from the XWindows walkthrough from above

>Note: Sadly, the Pulse is not currently working
 
1. Download the PulseAudio build for windows from http://code.x2go.org/releases/binary-win32/3rd-party/pulse/pulseaudio-5.0-rev18.zip

2. Extract the zip file to a folder like c:\work\wsl\pulse\

3. Get your IP address (see above)

4. Edit the configurations:
    1. create a new file 'config.pa' (c:\work\wsl\pulse\config.pa)
    2. add the following lines (REPLACE 192.168.1.111 with your IP address):   
```
        load-module module-native-protocol-tcp port=4713 auth-ip-acl=192.168.1.111
        load-module module-esound-protocol-tcp port=4714 auth-ip-acl=192.168.1.111        
        load-module module-waveout
```
    
5. execute: pulseaudio.exe -F config.pa --use-pid-file=false --exit-idle-time=-1
    The pulse audio server should be running.

6. In your Linux distro you need to export the PULSE_SERVER variable (the same process as for XWindows above)
    1. To start Linux type: bash
    2. echo "export PULSE_SERVER=tcp:192.168.1.111" >> ~/.bashrc # REPLACE 192.168.1.111 with your IP address
    3. source ~/.bashrc
    
    If your IP address changes, you will need to update the export for PULSE_SERVER.
    
7. You need to set an inbound firewall rule for Pulse audio. See the steps in setting up XWindows. If you have the rule for XWindows communication, you can skip this step.

8. Test it from Linux:
    1. sudo apt-get install libpulse0 -y
    2. paplay /mnt/c/Windows/Media/chimes.wav

Note: pulse audio has to be started every time if you want to hear sound from WSL. As the original article describes, you can create a service from the pulseaudio.exe (or from any other, by the way) using NSSM (http://nssm.cc/). Refer to the original article on details.
    
# Links

* https://github.com/microsoft/WSL/issues/4139
* https://stackoverflow.com/questions/61110603/how-to-set-up-working-x11-forwarding-on-wsl2
* https://kenny.yeoyou.net/it/2020/09/10/windows-development-environment.html
* https://www.hanselman.com/blog/the-easy-way-how-to-ssh-into-bash-and-wsl2-on-windows-10-from-an-external-machine
* https://superuser.com/questions/1305738/using-gnome-desktop-on-windows-wsl-version-of-ubuntu
* https://docs.microsoft.com/en-us/windows/wsl/troubleshooting
* https://www.shogan.co.uk/how-tos/wsl2-gui-x-server-using-vcxsrv/
* https://skeptric.com/wsl2-xserver/
