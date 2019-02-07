clear

# variables
$GitRepo = "https://github.com/mrjamiebowman/SampleDotNet-Powershell"
$GitFolder = "SampleDotNet"
$GitBranch = "develop"

# variables: iis
$SiteName = "SampleDotNet"
$IisWebsiteFolder = "SampleDotNet"
$SiteHostname = "localhost.sampledotnet.com"
$Username = $env:UserName
$WildcardSsl = "*.sampledotnet.com"

# msbuild
$SolutionFile = "SampleDotNet.sln"


Write-Host "*************************************************"
Write-Host "Set up IIS Website with PowerShell"
Write-Host "Script By: @mrjamiebowman"
Write-Host "*************************************************"

# check if in admin mode
Write-Host "Checking for Admin Mode"

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
{
    Write-Host "Not running in Admin Mode..."
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
} else {
    Write-Host "Running in Admin Mode..."
}

# used for setting up app pool
$Password = Read-Host -AsSecureString "Please enter your Windows Password"

# get Path
$RootPath = Get-Location
$Path = Join-Path $RootPath $GitFolder
Write-Host "Solution Path: $Path"


# validate Path
$CloneRepo = $true

if (Test-Path -Path $Path) {
    $Confirmation = Read-Host -Prompt "Project Path already exists. Do you want to overwrite (y/n)?"

    if ($Confirmation -eq 'y') {
        # remove directory and it's contents
        Write-Host "Removing existing directory..."
        Remove-Item -Recurse -Force -Path $Path
    } else {
        $CloneRepo = $false
    }
}


# git
if ($CloneRepo -eq $true) {
    Write-Host "Cloning remote repository locally."
    git clone $GitRepo $GitFolder 2>$null
    Set-Location -Path $Path

    if (![string]::IsNullOrEmpty($GitBranch)) {
        Write-Host "Checking out '$GitBranch' locally"        
        git checkout -b $GitBranch origin/$GitBranch 2>$null
    }
}


# hosts file
$HostsPath = "$env:SystemRoot\System32\Drivers\etc\hosts"

# hosts file: strip out commented fields and empty lines
[regex]$r="\S"
$HostsData = Get-Content $HostsPath | Where {
    (($r.Match($_)).value -ne "#") -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0)
}

$FoundHostEntry1 = $false
$FoundHostEntry2 = $false

$HostsData | foreach {
    #created named values
    $_ -match "(?<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?<HOSTNAME>\S+)" | Out-Null
    $ip=$matches.ip
    $hostname=$matches.hostname

    if ($ip -eq "127.0.0.1" -and $hostname -eq $SiteHostname) {
        $FoundHostEntry1 = $true
    }
    if ($ip -eq "::1" -and $hostname -eq $SiteHostname) {
        $FoundHostEntry2 = $true
    }
}

# hosts
Write-Host "Inspecting host file..."

$obj = New-Object PSObject
$obj | Add-Member Noteproperty -name "IP" -Value "127.0.0.1"
$obj | Add-Member Noteproperty -name "Hostname" -Value $SiteHostname    
write $obj
$obj.IP = "::1"
write $obj

# hosts file: entries
if ($FoundHostEntry1 -eq $true -and $FoundHostEntry2 -eq $true) {    
    Write-Host "Host file already contains both local host DNS settings."
    Write-Host ""
} else {
    # create entries
    Write-Host "Creating host file entries"
    Write-Host ""

    "`n" | Out-File -encoding ASCII -append $HostsPath
    "127.0.0.1" + "`t`t" + $SiteHostname | Out-File -encoding ASCII -append $HostsPath
    "::1" + "`t`t`t`t" + $SiteHostname | Out-File -encoding ASCII -append $HostsPath
}


# iis
Import-Module WebAdministration

# iis: certificate

# iis: app pool
New-WebAppPool $SiteName
Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName=$Username; password=$password; identitytype=3}

# iis: set up website
New-WebSite -Name $SiteName -PhysicalPath $Path\$IisWebsiteFolder -ApplicationPool $SiteName -Force
$IISSite = "IIS:\Sites\$SiteName"
Set-ItemProperty $IISSite -name  Bindings -value @{protocol="https";bindingInformation="*:443:$SiteHostname"}
Start-WebSite -Name $SiteName


# build
if (Test-Path "$path\package.json") {
    Write-Host "package.json file found... running npm install.."
    npm install
}

# msbuild
Install-Module -Name Invoke-MsBuild 

Invoke-MSBuild "$SolutionFile"


# open in chrome
Start-Process "chrome.exe" "https://$SiteHostname"