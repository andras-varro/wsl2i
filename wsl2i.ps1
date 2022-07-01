param ([string]$firewall_rule_name='WSL Server', [string]$host_ip, [string]$pulse_path="$env:ProgramFiles\Pulse", [string]$maintain="", [string]$distro="ubuntu") 

$wsl2_kernel_link="https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$wsl2_kernel_sha1="E6F3F03FA7C3248B006E23141C7692B47AFE3759"
$wsl_distro_link="https://aka.ms/wslubuntu2004"
$wsl_distro_sha1="FED6EB0B0E18C395B3A0F37C036678D5B67DB919"
$wsl_distro_use_this_sub_appx=""
$distro_local_path="$Env:SystemDrive\Linux\ubuntu2004"
$distro_search_pattern="U.b.u.n.t.u.-.2.0...0.4"
$distro_name="Ubuntu-20.04"
$distro_setup_file="ubuntu2004.exe"
$xsrv_link="https://sourceforge.net/projects/vcxsrv/files/vcxsrv/1.20.9.0/vcxsrv-64.1.20.9.0.installer.exe/download"
$xsrv_sha1="9FE0D6516AED298EED4159028AECA2105743F0F3"
$xsrv_executable="vcxsrv.exe"
$xsrv_start_arguments=":0 -ac -terminate -lesspointer -multiwindow -clipboard -nowgl"
$pulse_audio_link="http://code.x2go.org/releases/binary-win32/3rd-party/pulse/pulseaudio-5.0-rev18.zip"
$pulse_audio_sha1="2DB4D750F299B6B5DF5A541216C0882745F55399"
$default_nameserver_ip="8.8.8.8"
$use_windows_nameserver=$false

function UseDebianDistro()
{
    $global:wsl_distro_link="https://aka.ms/wsl-debian-gnulinux"
    $global:wsl_distro_sha1="19a369332ee015bb8ddb1dcf99553bebcfd068cb"
    $global:wsl_distro_use_this_sub_appx="DistroLauncher-Appx_1.12.1.0_x64.appx"
    $global:distro_local_path="$Env:SystemDrive\Linux\debian"
    $global:distro_search_pattern="D.e.b.i.a.n"
    $global:distro_name="Debian"
    $global:distro_setup_file="debian.exe"
    
    
    # Set-Variable -Name "wsl_distro_link" - value "https://aka.ms/wsl-debian-gnulinux" -scope global    
    # Set-Variable -Name "wsl_distro_sha1" - value "19a369332ee015bb8ddb1dcf99553bebcfd068cb" -scope global
    # Set-Variable -Name "wsl_distro_use_this_sub_appx" - value "DistroLauncher-Appx_1.12.1.0_x64.appx" -scope global
    # Set-Variable -Name "distro_local_path" - value "$Env:SystemDrive\Linux\debian" -scope global
    # Set-Variable -Name "distro_search_pattern" - value "D.e.b.i.a.n" -scope global
    # Set-Variable -Name "distro_name" - value "Debian" -scope global
    # Set-Variable -Name "distro_setup_file" - value "debian.exe" -scope global
}

function UseUbuntuDistro()
{
    $global:wsl_distro_link="https://aka.ms/wslubuntu2004"
    $global:wsl_distro_sha1="FED6EB0B0E18C395B3A0F37C036678D5B67DB919"
    $global:wsl_distro_use_this_sub_appx=""
    $global:distro_local_path="$Env:SystemDrive\Linux\ubuntu2004"
    $global:distro_search_pattern="U.b.u.n.t.u.-.2.0...0.4"
    $global:distro_name="Ubuntu-20.04"
    $global:distro_setup_file="ubuntu2004.exe"
    
    # Set-Variable -Name "wsl_distro_link" - value "https://aka.ms/wslubuntu2004" -scope global    
    # Set-Variable -Name "wsl_distro_sha1" - value "FED6EB0B0E18C395B3A0F37C036678D5B67DB919" -scope global
    # Set-Variable -Name "wsl_distro_use_this_sub_appx" - value "" -scope global
    # Set-Variable -Name "distro_local_path" - value "$Env:SystemDrive\Linux\ubuntu2004" -scope global
    # Set-Variable -Name "distro_search_pattern" - value "U.b.u.n.t.u.-.2.0...0.4" -scope global
    # Set-Variable -Name "distro_name" - value "Ubuntu-20.04" -scope global
    # Set-Variable -Name "distro_setup_file" - value "ubuntu2004.exe" -scope global
}

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
    return test-path $pulse_path    
}

function IsXServerInstalled([string]$xsrv_executable)
{
    $target_path=CheckForFile $ENV:ProgramFiles $xsrv_executable
    return ![string]::IsNullOrEmpty($target_path)
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
    
    if (!$?) 
    {
        ContinueOrExit "Execution of [$file_path] has failed"
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
        $result = wsl --set-default-version 2
    } 
    else 
    {
        echo "WSL2 kernel is available"
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

function DownloadDistroAndPrepareDirectory([string]$distro_local_path, [string] $wsl_distro_link, [string]$wsl_distro_sha1)
{
    $local_file_path="$env:TEMP\distro.zip"
    
    if ( (test-path "$local_file_path") -and (CheckHash "$local_file_path" $wsl_distro_sha1) )
    {
        $header = 'Distro installer is available locally'
        $text = "The distro is not installed, but apparently the installer is available in the file system under [$local_file_path]. Do you want to use the local copy?"
        $choices = '&Yes', '&No'

        $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
        if ($answer -ne 0) {
            DownloadAndCheckCRC $wsl_distro_link $local_file_path $wsl_distro_sha1
        } 
    }
    else
    {
        ContinueOrExit "Downloading distro image, this can take a while (usual size is around 500Mb)"
        DownloadAndCheckCRC $wsl_distro_link $local_file_path $wsl_distro_sha1
    }
    
    if ($wsl_distro_use_this_sub_appx -ne "")
    {
        $random_temp_dir_name = GetRandomTempFolder
        Unzip $local_file_path $random_temp_dir_name
        $zip_name = [System.IO.Path]::ChangeExtension("$random_temp_dir_name\$wsl_distro_use_this_sub_appx",".zip")
        # unzip checks the extension. if it is not *.zip it fails.
        rename-item -path "$random_temp_dir_name\$wsl_distro_use_this_sub_appx" -newname $zip_name
        Unzip "$zip_name" $distro_local_path
    }
    else
    {
        Unzip $local_file_path $distro_local_path
    }
    icacls $distro_local_path /t /grant "Everyone:(OI)(CI)F"
    if (!$?) 
    {
        ContinueOrExit "Setting the rights for the distro image failed"
    }
}

function GetRandomTempFolder ()
{
    return "$env:TEMP\"+[System.IO.Path]::GetRandomFileName()
}

function SelectDistro ()
{
    if ($distro -eq "debian")
    {
        UseDebianDistro
    }    
    else
    {
        UseUbuntuDistro
    }
}

function QueryDistroAndInstall ([string]$distro_local_path, [string] $wsl_distro_link, [string]$wsl_distro_sha1, [string]$distro_search_pattern, [string]$distro_setup_file, [string]$wsl_distro_use_this_sub_appx)
{
    echo "Querying for distro..."
    $is_distro_available = $false
    [string[]]$result =wsl -l
    foreach ($i in $result) {
       if ( (echo $i | Select-String -pattern $distro_search_pattern).Matches.Count -ne 0 ) { 
           $is_distro_available = $true
           break 
       }
    }

    if ( ! $is_distro_available ) {
        if ( Test-Path "$distro_local_path\$distro_setup_file" )
        {
            $header = 'Distro available locally'
            $text = "The distro is not registered, but apparently it is available in the file system under [$distro_local_path\$distro_setup_file]. Do you want to use the local copy?"
            $choices = '&Yes', '&No'

            $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
            if ($answer -ne 0) {
                DownloadDistroAndPrepareDirectory $distro_local_path $wsl_distro_link $wsl_distro_sha1
            } 
        }
        else 
        {
            DownloadDistroAndPrepareDirectory $distro_local_path $wsl_distro_link $wsl_distro_sha1
        }

        StartProcess "Starting Distro installer. Please follow the on screen instructions, and when the bash prompt is displayed, type `exit` to continue with the setup." "$distro_local_path\$distro_setup_file"        
        echo "Continuing installer"
    } 
    else 
    {
        echo "Distro image is available."
    }
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
    
    $argument="wget -q --spider http://google.com; if [[ $? -ne 0 ]]; then read -p 'WSL DNS is not working. To fix the DNS issue in WSL, we need to execute elevated commands (sudo). WSL will ask you for your Linux password. Press any key to start ...'; cd /etc; echo '[network]' | sudo tee wsl.conf; echo 'generateResolvConf = false' | sudo tee -a wsl.conf; sudo rm -Rf resolv.conf; $resolv_conf_command else echo 'WSL DNS is working'; fi"
    StartProcess "" "wsl" $argument
    wsl --shutdown
}

function MaintainExportDisplay ([string]$host_ip)
{
    $Argument_Export_Display="if grep '^export DISPLAY' ~/.bashrc ; then  sed -i -r 's|^(export DISPLAY\s*=\s*).*|\1$host_ip"+":0|' ~/.bashrc ; else echo export DISPLAY=$host_ip"+":0 >> ~/.bashrc ; fi ; grep '^export DISPLAY' ~/.bashrc"
    StartProcess "Maintain ~.bashrc on default distro for DISPLAY" "wsl" "$Argument_Export_Display"
}

function DoSetupForXWindows ([string]$host_ip, [string]$xsrv_link, [string]$xsrv_sha1)
{
    $local_file_path="$env:TEMP\xsrv_installer.exe"
    DownloadAndCheckCRC $xsrv_link $local_file_path $xsrv_sha1
    & $local_file_path /S
    MaintainExportDisplay $host_ip
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

function SetupXWindows ([string]$host_ip, [string]$xsrv_link, [string]$xsrv_sha1, [string]$xsrv_executable, [string]$xsrv_start_arguments)
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
        
        DoSetupForXWindows $host_ip $xsrv_link $xsrv_sha1
        $target_path=CheckForFile $ENV:ProgramFiles $xsrv_executable
        if ([string]::IsNullOrEmpty($target_path))
        {
            echo "Unable to create shorcut for $xsrv_executable, the file cannot be located under $ENV:ProgramFiles"
            return
        }
    }
    
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

function MaintainExportPulse ([string]$host_ip)
{
    $Argument_Export_Pulse="if grep '^export PULSE_SERVER' ~/.bashrc ; then  sed -i -r 's|^(export PULSE_SERVER\s*=\s*).*|\1tcp:"+"$host_ip|' ~/.bashrc ; else echo export PULSE_SERVER=tcp:"+"$host_ip >> ~/.bashrc ; fi ; grep '^export PULSE_SERVER' ~/.bashrc"
    
    StartProcess "Maintain ~.bashrc on default distro for PULSE_SERVER" "wsl" "$Argument_Export_Pulse"
}

function DoSetupForPulse ([string]$host_ip, [string]$pulse_path, [string]$pulse_audio_link, [string]$pulse_audio_sha1)
{
    $local_file_path="$env:TEMP\pulse.zip"
    DownloadAndCheckCRC $pulse_audio_link $local_file_path $pulse_audio_sha1
    Unzip $local_file_path $pulse_path
    Move-Item "$pulse_path\pulse\*" $pulse_path
    MaintainPulse $host_ip $pulse_path
    MaintainExportPulse $host_ip
}

function CreateShortcutsForPulse([string]$pulse_path)
{
    $shortcut_name="PulseWslAudioServer"
    $target_path="$pulse_path\pulseaudio.exe"
    $argument="-F config.pa --use-pid-file=false --exit-idle-time=-1"
    CreateStartMenuShortcut $shortcut_name $target_path $argument $pulse_path
    CreateAutostartShortcut $shortcut_name $target_path $argument $pulse_path
}

function SetupPulseAudio ([string]$host_ip, [string]$pulse_path, [string]$pulse_audio_link, [string]$pulse_audio_sha1)
{
    $target_path=CheckForFile $pulse_path "pulseaudio.exe"
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
        $target_path=CheckForFile $pulse_path "pulseaudio.exe"
        if ([string]::IsNullOrEmpty($target_path))
        {
            echo "Unable to create shorcut for pulseaudio.exe, the file cannot be located under $pulse_path"
            return
        }
    }
    
    CreateShortcutsForPulse $pulse_path
}

function DoMaintainFirewall ([string]$firewall_rule_name, [string]$host_ip)
{
    Get-NetFirewallRule -Displayname "$firewall_rule_name" > $null 2>&1
    if ( !$? ) { 
        echo "Creating firewall rule for WSL Server [$firewall_rule_name]"
        New-NetFirewallRule -DisplayName $firewall_rule_name -RemoteAddress $host_ip -LocalAddress $host_ip -Direction inbound -Profile 'Domain, Private' -Action Allow
    } else {
        $wsl_firewall_ip=(Get-NetFirewallRule -Displayname "$firewall_rule_name" | Get-NetFirewallAddressFilter).RemoteAddress
        if ( !$? ) {
            echo "Firewall rule [$firewall_rule_name] is not available"
            return
        }

        if ( $wsl_firewall_ip -ne $host_ip ) {
            echo "Setting address in firewall rule for WSL Server"
            Get-NetFirewallRule -DisplayName $firewall_rule_name | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $host_ip -LocalAddress $host_ip
        }
        else
        {
            echo "Firewall rule [$firewall_rule_name] is OK"
        }
    }
}

function MaintainFirewall ([string]$firewall_rule_name, [string]$host_ip)
{
    Get-NetFirewallRule -Displayname "$firewall_rule_name" > $null 2>&1
    if ( !$? )
    {
        $header = 'Maintain firewall rules'
        $text = 'Do you want to check and maintain or create firewall rules? It is necessary for X Windows and audio servers to work.'
        $choices = '&Yes', '&No'
        $answer = $Host.UI.PromptForChoice($header, $text, $choices, 1)
        if ($answer -ne 0) {
            echo "Firewall rule is not set up. X Windows and Audio from WSL might not work."
            return        
        }        
    }
    
    DoMaintainFirewall $firewall_rule_name $host_ip
}

function SetDistroDefault ([string]$distro_name)
{
    echo "Setting $distro_name as default."
    & wsl -s $distro_name
}

function MaintainOnly ([string]$host_ip, [string]$firewall_rule_name, [string]$pulse_path, [string]$xsrv_executable, [string]$distro_name, [string]$default_nameserver_ip, [bool]$use_windows_nameserver)
{
    SetDistroDefault $distro_name
    CheckAndFixWslDns $default_nameserver_ip $use_windows_nameserver
    
    [bool]$is_pulse_installed=IsPulseInstalled $pulse_path
    [bool]$is_xsrv_installed=IsXServerInstalled $xsrv_executable
    
    if ( $is_pulse_installed -OR $is_xsrv_installed )
    {
        DoMaintainFirewall $firewall_rule_name $host_ip
    }
    
    if ( $is_xsrv_installed )
    {
        MaintainExportDisplay $host_ip
    }
    
    if ( $is_pulse_installed ) 
    { 
        MaintainPulse $host_ip $pulse_path
        MaintainExportPulse $host_ip
    }
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
    
    if (! [string]::IsNullOrEmpty($maintain) )
    {
        echo "Performing maintaintenance only for image $maintain"
        
        MaintainOnly $host_ip $firewall_rule_name $pulse_path $xsrv_executable $maintain $default_nameserver_ip $use_windows_nameserver
        exit
    }
    
    SelectDistro
    
    echo "Host IP: $host_ip"
    echo "Firewall rule name: $firewall_rule_name"
    echo "Pulse audio path: $pulse_path"
    echo "Distro local path: $global:distro_local_path"
    
    CheckWindowsReleaseId
    QueryHypervStateAndInstall $script_path
    QueryWSLStateAndInstall $script_path
    QueryWsl2AndInstall $wsl2_kernel_link $wsl2_kernel_sha1
    QueryDistroAndInstall $global:distro_local_path $global:wsl_distro_link $global:wsl_distro_sha1 $global:distro_search_pattern $global:distro_setup_file $global:wsl_distro_use_this_sub_appx
    SetDistroDefault $global:distro_name
    CheckAndFixWslDns $default_nameserver_ip $use_windows_nameserver
    SetupXWindows $host_ip $xsrv_link $xsrv_sha1 $xsrv_executable $xsrv_start_arguments
    SetupPulseAudio $host_ip $pulse_path $pulse_audio_link $pulse_audio_sha1
    
    [bool]$is_pulse_installed=IsPulseInstalled $pulse_path
    [bool]$is_xsrv_installed=IsXServerInstalled $xsrv_executable
    if ( $is_pulse_installed -OR $is_xsrv_installed )
    {
        MaintainFirewall $firewall_rule_name $host_ip 
    }
#}




