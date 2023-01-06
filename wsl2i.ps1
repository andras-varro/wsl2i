param ([string]$firewall_rule_name='WSL Server', [string]$pulse_path="$env:ProgramFiles\Pulse", [string]$distro="Ubuntu-20.04") 

$wsl2_kernel_link="https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$wsl2_kernel_sha1="E6F3F03FA7C3248B006E23141C7692B47AFE3759"
$xsrv_link="https://sourceforge.net/projects/vcxsrv/files/vcxsrv/1.20.9.0/vcxsrv-64.1.20.9.0.installer.exe/download"
$xsrv_sha1="9FE0D6516AED298EED4159028AECA2105743F0F3"
$xsrv_executable="vcxsrv.exe"
$xsrv_start_arguments=":0 -ac -terminate -lesspointer -multiwindow -clipboard -nowgl"
$pulse_audio_link="http://code.x2go.org/releases/binary-win32/3rd-party/pulse/pulseaudio-5.0-rev18.zip"
$pulse_audio_sha1="2DB4D750F299B6B5DF5A541216C0882745F55399"
$pulse_audio_executable="pulseaudio.exe"
$default_nameserver_ip="8.8.8.8"
$use_windows_nameserver=$false

function ContinueOrExit([string]$message)
{
    echo "$message. Press Ctrl+C to cancel." 
    pause
}

function RestartComputer([string]$script_path)
{
    ContinueOrExit "Restart needed"
    $argument="powershell -command ""start-process -verb RunAs -FilePath \""powershell.exe\"" -ArgumentList \""-file\"",\""\""\""$script_path\""\""\"""""
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name 'SetupWSL' -Value "$argument"
    echo "Suspending BitLocker..."
    Suspend-BitLocker -MountPoint "C:" -RebootCount 1
    shutdown /r /t 0
    exit
}

function IsPulseInstalled([string]$pulse_path)
{
	$target_path=CheckForFile $pulse_path "$pulse_audio_executable"	
	return $target_path
}

function IsXServerInstalled([string]$xsrv_executable)
{
    $target_path=CheckForFile $ENV:ProgramFiles $xsrv_executable
    return $target_path
}

function CheckWindowsReleaseId()
{
    echo "Querying Windows ReleaseId..."
    $win_ver=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    echo "Win ver: $win_ver"
    $converted=0
    if (!([int]::TryParse($win_ver, [ref]$converted)) -or ($converted -lt 1903)) { 
        ContinueOrExit "This version might not support WSL2."
    }    
}

function QueryHostIp()
{
    $host_ip = (Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
    ).IPv4Address.IPAddress
    
    if ( [string]::IsNullOrEmpty($host_ip) )
    {
        ContinueOrExit "Unable to determine host IP. You can specify the host's IP as a parameter to the script. Without the IP the script will not work"
    }
    
    return $host_ip
}

function QueryHypervStateAndInstall([string] $script_path)
{
    echo "Querying Hyper-V state..."
    $hyperv_state = (Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online).State
    echo "Hyper-V: $hyperv_state"
    if ($hyperv_state -ne "Enabled") {
        ContinueOrExit "Enabling Hyper-V"
        $result=Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        if ($result.RestartNeeded) { 
            RestartComputer $script_path
        }
    }
}

function QueryWSLStateAndInstall([string] $script_path)
{
    echo "Querying WSL state..."
    $wsl_state = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State
    echo "WSL state: $wsl_state"
    if ($wsl_state -ne "Enabled") {
        ContinueOrExit "Enabling WSL"
        $result=Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        if ($result.RestartNeeded) { 
            RestartComputer $script_path
        }
    }
}

function DownloadAndCheckCRC([string]$url, [string]$local_file_path, [string]$supplied_hash)
{
    echo "Downloading. See progress above..."
    Invoke-WebRequest -Uri $url -OutFile $local_file_path -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    if (!$?) 
    { 
        ContinueOrExit "Download of url [$url] failed."
    }
    
    if ( $hash -ne "" )
    {
        # $computed_hash=$(Get-FileHash -Algorithm SHA1 $local_file_path).Hash
        # if ( $computed_hash -eq $supplied_hash ) 
        if (CheckHash "$local_file_path" $supplied_hash)
        {
            echo "Download of url [$url] completed. Hash check is OK."
            return 
        }
        
        ContinueOrExit "Computed hash [$computed_hash] for file [$local_file_path], downloaded from [$url] is not equals the supplied hash [$supplied_hash]. Maybe a newer version? Continue at your own risk"
        return        
    }
    
    echo "Download of url [$url] completed. No hash supplied, hash check not performed."
}

function CheckHash ([string]$local_file_path, [string]$supplied_hash)
{
    $computed_hash=$(Get-FileHash -Algorithm SHA1 "$local_file_path").Hash
    return ( $computed_hash -eq $supplied_hash ) 
}

function StartProcess([string]$message, [string]$file_path, [string]$argument_list)
{
    if ( $message -ne "" )
    {
        echo $message
    }
	
    if ( $argument_list -eq "" ) 
    {
        $executed_process=Start-Process -Wait -NoNewWindow -PassThru -FilePath $file_path
    }
    else
    {
        $executed_process=Start-Process -Wait -NoNewWindow -PassThru -FilePath $file_path -ArgumentList $argument_list 
    }
	
	$exit_code = $executed_process | select -ExpandProperty "ExitCode"
	
    if ($exit_code -ne 0) 
    {
        ContinueOrExit "Execution of [$file_path] has failed"
		$global:procSuccess=$false
    }
	else
	{
		$global:procSuccess=$true
	}
}

function QueryWsl2AndInstall([string]$wsl2_kernel_link, [string]$wsl2_kernel_sha1)
{
    echo "Querying WSL2 kernel status..."
    [string[]]$result = wsl --set-default-version 2
    if ($result.Length -lt 1) 
    { 
        ContinueOrExit "Unable to determine the status of WSL2"
    }

    $matchInfo = echo $result[0] | Select-String -pattern "h.t.t.p.s.:././.a.k.a...m.s./.w.s.l.2.k.e.r.n.e.l"
    $wsl2_available = $matchInfo.Matches.Count -eq 0
    if ( !  $wsl2_available ) 
    {
        echo "WSL2 kernel is not available"
        ContinueOrExit "Downloading WSL2 kernel"
        $local_file_path="$env:TEMP\wsl_update_x64.msi" 
        DownloadAndCheckCRC $wsl2_kernel_link $local_file_path $wsl2_kernel_sha1
        StartProcess "Installing WSL2 kernel." "msiexec.exe" "/i $local_file_path /qn" 
		if ( ! $global:procSuccess )
		{
			ContinueOrExit "Install of WSL2 kernel failed"
			return
		}
		else
		{
			$result = wsl --set-default-version 2
		}
    } 
    else 
    {
        echo "WSL2 kernel is available"
    }
	
	wsl --update
	if ( !$? ) {
	  ContinueOrExit "Update to latest WSL2 kernel failed"
	}
}

function Unzip ([string]$source_path, [string] $target_path)
{
    echo "Extracting archive... See progress above"
    if (Test-Path $target_path) 
    {
        Remove-Item $target_path -Force -Confirm:$false -Recurse
    }
    
    Expand-Archive -Path $source_path -DestinationPath $target_path -Force
    if (!$?) 
    {
        ContinueOrExit "Unzip of [$source_path] has failed"
    }
}

function GetRandomTempFolder ()
{
    return "$env:TEMP\"+[System.IO.Path]::GetRandomFileName()
}

function QueryDistroAndInstall ([string]$distro_name)
{
    echo "Querying for distro $distro_name"
    $is_distro_available = $false
	echo "Available distros:"
    [string[]]$result =wsl -l -q
    foreach ($i in $result) {
		if ( $i -eq $distro_name ) {
           $is_distro_available = $true
           break 
       }
    }

    if ( ! $is_distro_available ) {
        StartProcess "Starting Distro installer. Please follow the on screen instructions, and when the bash prompt is displayed, type `exit` to continue with the setup." "wsl.exe" "--install -d $distro_name --web-download"
		if ( ! $global:procSuccess ) {
			ContinueOrExit "Distro install failed"
			$global:distroAvailable=$false
			return
		}
		
        ContinueOrExit "Please wait for the distro installer to finish"
    } 
    else 
    {
        echo "Distro already available. If you want to install the same distro as a different instance, you need to rename the existing one. See https://superuser.com/questions/1507237/how-to-change-the-name-of-a-wsl-distro-to-reflect-the-actual-distro"
    }
	
	$global:distroAvailable=$true
}

function GetWindowsDnsServer ()
{
    [string[]]$dns_servers=((Get-NetIPConfiguration | 
        Where-Objectcd { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).DNSServer | 
            Where-Object {$_.AddressFamily -eq 2}).ServerAddresses
    
    return $dns_servers
}

function CheckAndFixWslDns ([string]$default_nameserver_ip, [bool]$use_windows_nameserver)
{
    if ( $use_windows_nameserver )
    {
        [string[]]$dns_servers=GetWindowsDnsServer
        $resolv_conf_command="echo ""nameserver " + $dns_servers[0]+ """ | sudo tee resolv.conf;"
        if ( $dns_servers.Length -gt 1 ) {
            $resolv_conf_command=$resolv_conf_command + " echo ""nameserver " + $dns_servers[1]+ """ | sudo tee -a resolv.conf;"
        } else {
            $resolv_conf_command=$resolv_conf_command + " echo ""nameserver $default_nameserver_ip"" | sudo tee -a resolv.conf;"
        }
    }
    else
    {
        $resolv_conf_command="echo ""nameserver $default_nameserver_ip"" | sudo tee resolv.conf;"
    }
    
    $argument="wget -q --spider http://google.com; if [[ "+'$?'+" -ne 0 ]]; then read -p 'WSL DNS is not working. To fix the DNS issue in WSL, we need to execute elevated commands (sudo). WSL will ask you for your Linux password. Press any key to start ...'; cd /etc; echo '[network]' | sudo tee wsl.conf; echo 'generateResolvConf = false' | sudo tee -a wsl.conf; sudo rm -Rf resolv.conf; $resolv_conf_command else echo 'WSL DNS is working'; fi"
    StartProcess "" "wsl" $argument
	if ( ! $global:procSuccess )
	{
		ContinueOrExit "Failed to perform check and fix for DNS"
	}
	
    wsl --shutdown
}

function MaintainExportDisplay ()
{
	$findIp='$(route.exe print | grep 0.0.0.0 | head -1 | awk ''\''''{print $4;}''\''''):0'
    $Argument_Export_Display="if ( ! grep 'export DISPLAY=$findIp' ~/.bashrc ) ; then echo 'export DISPLAY=$findIp' >> ~/.bashrc; fi"
    StartProcess "Maintain ~.bashrc on default distro for DISPLAY" "wsl" "$Argument_Export_Display"
	if ( ! $global:procSuccess )
	{
		ContinueOrExit "Failed to perform manitenance on Export DISPLAY"
	}
}

function DoSetupForXWindows ([string]$xsrv_link, [string]$xsrv_sha1)
{
    $local_file_path="$env:TEMP\xsrv_installer.exe"
    DownloadAndCheckCRC $xsrv_link $local_file_path $xsrv_sha1
    & $local_file_path /S
}

function CreateShortcut([string]$shortcut_name, [string]$target_path, [string]$argument, [string]$special_folder, [string]$working_directory)
{
    $WshShell = New-Object -comObject WScript.Shell
    $strStartup = $WshShell.SpecialFolders("$special_folder")
    $oMyShortCut= $WshShell.CreateShortcut($strStartup+"\$shortcut_name.lnk")
    $oMyShortCut.TargetPath = $target_path
    $oMyShortCut.Arguments = $argument
    $oMyShortCut.WorkingDirectory = $working_directory
    $oMyShortCut.Save()
}

function CheckForFile ([string]$folder, [string]$file_name)
{
    $target_path=& where.exe /R "$folder" "$file_name" 2>$null
    return $target_path
}

function CreateAutostartShortcut([string]$shortcut_name, [string]$target_path, [string]$argument, [string]$working_directory)
{    
    $startup_path=[Environment]::GetFolderPath('Startup')
    $shortcut_path=CheckForFile $startup_path "$shortcut_name.lnk"
    if ( ! [string]::IsNullOrEmpty($shortcut_path) )
    {
         echo "$shortcut_name shortcut is available in the Startup folder: $startup_path\$shortcut_name.lnk"
         return
    }
    
    $header = 'Setup Autostart'
    $text = "Do you want to set-up $shortcut_name to start automatically with Windows?"
    $choices = '&Yes', '&No'
    
    $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
    if ($answer -ne 0) 
    {
        echo "$shortcut_name needs to be started manually from Start Menu."
        return        
    }
    
    CreateShortcut $shortcut_name $target_path $argument "Startup" $working_directory
}

function CreateStartMenuShortcut([string]$shortcut_name, [string]$target_path, [string]$argument, [string]$working_directory)
{
    $start_menu=[Environment]::GetFolderPath('StartMenu')
    $shortcut_path=CheckForFile $start_menu "$shortcut_name.lnk"
    if ( ! [string]::IsNullOrEmpty($shortcut_path) )
    {
        echo "$shortcut_name shortcut is available in Start Menu: $start_menu\$shortcut_name.lnk"
    }
    else
    {        
        CreateShortcut $shortcut_name $target_path $argument "StartMenu" $working_directory
    }
}

function CreateShortcutsForXWindows([string]$target_path, [string]$xsrv_start_arguments)
{
    $shortcut_name="X-Windows-Server"
    CreateStartMenuShortcut $shortcut_name $target_path $xsrv_start_arguments $ENV:ProgramFiles
    CreateAutostartShortcut $shortcut_name $target_path $xsrv_start_arguments $ENV:ProgramFiles
}

function SetupXWindows ([string]$xsrv_link, [string]$xsrv_sha1, [string]$xsrv_executable, [string]$xsrv_start_arguments)
{
    $target_path=CheckForFile $ENV:ProgramFiles $xsrv_executable
    if ( ![string]::IsNullOrEmpty($target_path) )
    {
        echo "X-Windows Server is installed under [$target_path]"
    }
    else
    {
        $header = 'Setup X-Windows Server'
        $text = 'Do you want to set-up X-Window support for WSL?'
        $choices = '&Yes', '&No'

        $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
        if ($answer -ne 0) {
            echo "XWindows setup is cancelled"
            return        
        } 
        
        DoSetupForXWindows $xsrv_link $xsrv_sha1
        $target_path=CheckForFile $ENV:ProgramFiles $xsrv_executable
        if ([string]::IsNullOrEmpty($target_path))
        {
            echo "Unable to create shorcut for $xsrv_executable, the file cannot be located under $ENV:ProgramFiles"
            return
        }
    }
    
	MaintainExportDisplay
    CreateShortcutsForXWindows $target_path $xsrv_start_arguments
}

function MaintainPulse ([string]$host_ip, [string]$pulse_path)
{
    if (Test-Path $pulse_path) {
        echo "Maintain pulse at $pulse_path"
        echo "load-module module-native-protocol-tcp port=4713 auth-ip-acl=$host_ip" | Out-File -Encoding ASCII -FilePath "$pulse_path\config.pa"
        echo "load-module module-esound-protocol-tcp port=4714 auth-ip-acl=$host_ip" | Out-File -Append -Encoding ASCII -FilePath "$pulse_path\config.pa"
        echo "load-module module-waveout" | Out-File -Append -Encoding ASCII -FilePath "$pulse_path\config.pa"
    }
}

function MaintainExportPulse ()
{
	$findIp='$(route.exe print | grep 0.0.0.0 | head -1 | awk ''\''''{print $4;}''\'''')'
    $Argument_Export_Pulse="if ( ! grep 'export PULSE_SERVER=tcp:$findIp' ~/.bashrc ) ; then echo 'export PULSE_SERVER=tcp:$findIp' >> ~/.bashrc; fi"
    StartProcess "Maintain ~.bashrc on default distro for PULSE_SERVER" "wsl" "$Argument_Export_Pulse"
	if ( ! $global:procSuccess )
	{
		ContinueOrExit "Failed to perform manitenance on Export PULSE_SERVER"
	}
}

function DoSetupForPulse ([string]$host_ip, [string]$pulse_path, [string]$pulse_audio_link, [string]$pulse_audio_sha1)
{
    $local_file_path="$env:TEMP\pulse.zip"
    DownloadAndCheckCRC $pulse_audio_link $local_file_path $pulse_audio_sha1
    Unzip $local_file_path $pulse_path
    Move-Item "$pulse_path\pulse\*" $pulse_path
    MaintainPulse $host_ip $pulse_path
}

function CreateShortcutsForPulse([string]$pulse_path)
{
    $shortcut_name="PulseWslAudioServer"
    $target_path="$pulse_path\$pulse_audio_executable"
    $argument="-F config.pa --use-pid-file=false --exit-idle-time=-1"
    CreateStartMenuShortcut $shortcut_name $target_path $argument $pulse_path
    CreateAutostartShortcut $shortcut_name $target_path $argument $pulse_path
}

function SetupPulseAudio ([string]$host_ip, [string]$pulse_path, [string]$pulse_audio_link, [string]$pulse_audio_sha1)
{
    $target_path=CheckForFile $pulse_path "$pulse_audio_executable"
    if ( ![string]::IsNullOrEmpty($target_path) )
    {
        echo "Pulse Audio Server is installed under [$target_path]"
    }
    else
    {
        $header = 'Setup Pulse Audio Server'
        $text = 'Do you want to set-up Audio support for WSL?'
        $choices = '&Yes', '&No'

        $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
        if ($answer -ne 0) {
            echo "Audio setup is cancelled"
            return        
        } 
        
        DoSetupForPulse $host_ip $pulse_path $pulse_audio_link $pulse_audio_sha1
        $target_path=CheckForFile $pulse_path "$pulse_audio_executable"
        if ([string]::IsNullOrEmpty($target_path))
        {
            echo "Unable to create shorcut for $pulse_audio_executable, the file cannot be located under $pulse_path"
            return
        }
    }
    
	MaintainExportPulse
    CreateShortcutsForPulse $pulse_path
}

function MaintainFirewall ([string]$firewall_rule_name, [string]$xserver_exe_path, [string]$pulse_exe_path)
{
	if ([string]::IsNullOrEmpty($xserver_exe_path)) {
        echo "No xserver is installed, therefore no firewall modification is needed"
    }
	else {
		Get-NetFirewallRule -Displayname $firewall_rule_name'_XServer' > $null 2>&1
		if ( $? ) {
			echo "Firewall rule for xserver is already available, therefore no firewall modification is needed"
		}
		
		CreateFirewallRule $firewall_rule_name'_XServer' $xserver_exe_path '6000'
	}
	
	if ([string]::IsNullOrEmpty($pulse_exe_path)) {
        echo "No pulse audio is installed, therefore no firewall modification is needed"
    }
	else {
		Get-NetFirewallRule -Displayname $firewall_rule_name'_Pulse' > $null 2>&1
		if ( $? ) {
			echo "Firewall rule for pulse audio is already available, therefore no firewall modification is needed"
		}
	
		CreateFirewallRule $firewall_rule_name'_Pulse' $pulse_exe_path '4000'
	}
}

function CreateFirewallRule ([string]$firewall_rule_name, [string]$exe_path, [int]$port)
{
    Get-NetFirewallRule -Displayname "$firewall_rule_name" > $null 2>&1
    if ( $? ) { 
		echo "Firewall rule with name $firewall_rule_name is already available. Aborting."
		return
	}
	
	$header = "Create firewall rule: $firewall_rule_name"
	$text = "Do you want to create the firewall rule for $exe_path?"
	$choices = '&Yes', '&No'
	$answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
	if ($answer -ne 0) {
		echo "Firewall rule for $exe_path is not set up."
		return        
	} 

    new-NetFirewallRule -DisplayName $firewall_rule_name -Profile 'Domain, Private' -Direction 'Inbound' -Action 'Allow' -Protocol 'TCP' -LocalPort $port -Program $exe_path
    if ( $? ) { 
        echo "Creating firewall rule [$firewall_rule_name] succeeded."
    } else {
        ContinueOrExit "Creating firewall rule [$firewall_rule_name] has failed"
    }
}

function SetDistroDefault ([string]$distro_name)
{
    echo "Setting $distro_name as default."
    & wsl -s $distro_name
}

#function Main(string[]$args)
#{
    if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        $header = 'No admin rights'
        $text = 'The script was started without admin rights. If you continue, multiple functions would not work. Do you want to continue?'
        $choices = '&Yes', '&No'
        $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
        if ($answer -ne 0) {
            echo "Please re-run this script as an Administrator!"
            exit        
        }
		
        echo "Continuing without admin rights"
    }
    
    $script_path = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrEmpty($host_ip))
    {
        $host_ip=QueryHostIp
    }
        
    echo "Host IP: $host_ip"
    echo "Firewall rule name: $firewall_rule_name"
    echo "Pulse audio path: $pulse_path"
    echo "Distro name: $distro"
    
    CheckWindowsReleaseId
    QueryHypervStateAndInstall $script_path
    QueryWSLStateAndInstall $script_path
    QueryWsl2AndInstall $wsl2_kernel_link $wsl2_kernel_sha1
    QueryDistroAndInstall $distro
	if ( ! $global:distroAvailable )
	{
		echo "$distro is not available. Cannot operate."
		exit
	}
	
    SetDistroDefault $distro
    CheckAndFixWslDns $default_nameserver_ip $use_windows_nameserver
    SetupXWindows $xsrv_link $xsrv_sha1 $xsrv_executable $xsrv_start_arguments
    SetupPulseAudio $host_ip $pulse_path $pulse_audio_link $pulse_audio_sha1
    
    [string]$pulse_exe_path=IsPulseInstalled $pulse_path
    [string]$xserver_exe_path=IsXServerInstalled $xsrv_executable
    MaintainFirewall $firewall_rule_name $xserver_exe_path $pulse_exe_path
#}
