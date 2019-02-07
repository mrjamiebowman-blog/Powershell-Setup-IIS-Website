clear

# variables
$GitRepo = "https://github.com/mrjamiebowman/SampleDotNet-Powershell"
$GitFolder = "SampleDotNet"
$GitBranch = "develop"

# variables: iis
$SiteName = "SampleDotNet"
$IISWebsiteFolder = "SampleDotNet"
$SiteHostname = "localhost.sampledotnet.com"
$Username = $env:UserName
$WildcardSsl = "*.sampledotnet.com"

# msbuild
$SolutionFile = "SampleDotNet.sln"


Write-Host "*************************************************"
Write-Host "Set up IIS Website with PowerShell"
Write-Host "Script By: @mrjamiebowman"
Write-Host "*************************************************`n"

# check if in admin mode
Write-Host "Checking PowerShell is in Administrative Mode" -ForegroundColor Green

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
{
    Write-Host "Not running in Admin Mode...`n"
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
} else {
    Write-Host "Running in Admin Mode...`n"
}

Write-Host "Collecting Information..." -ForegroundColor Green

# used for setting up app pool
$Password = Read-Host -AsSecureString "Please enter your Windows Password for the Application Pool Identity"

# get Path
$RootPath = Get-Location
$Path = Join-Path $RootPath $GitFolder

Write-Host "Root Path: $RootPath"
Write-Host "Solution Path: $Path"



# validate Path
Write-Host ""
Write-Host "Validating Website Path" -ForegroundColor Green
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
Write-Host ""
Write-Host "Git Repository" -ForegroundColor Green

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
Write-Host ""
Write-Host "Hosts File" -ForegroundColor Green
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
        Write-Host "Found Host Entry #1 - $ip - $hostname"
        $FoundHostEntry1 = $true
    }
    if ($ip -eq "::1" -and $hostname -eq $SiteHostname) {
        Write-Host "Found Host Entry #2 - $ip - $hostname"
        $FoundHostEntry2 = $true
    }
}

# hosts
Write-Host ""
Write-Host "Inspecting host file..."

$obj = New-Object PSObject
$obj | Add-Member Noteproperty -name "IP" -Value "127.0.0.1"
$obj | Add-Member Noteproperty -name "Hostname" -Value $SiteHostname    
Write-Host $obj
$obj.IP = "::1"
Write-Host $obj

# hosts file: entries
if ($FoundHostEntry1 -eq $true -and $FoundHostEntry2 -eq $true) {    
    Write-Host "Host file already contains both local host DNS settings."
    Write-Host ""
} else {
    # create entries
    Write-Host "Creating host file entries"
    Write-Host ""

    "`n" | Out-File -encoding ASCII -append $HostsPath

    if ($FoundHostEntry1 -eq $false) {
        "127.0.0.1" + "`t`t" + $SiteHostname | Out-File -encoding ASCII -append $HostsPath
    }

    if ($FoundHostEntry2 -eq $false) {
        "::1" + "`t`t`t`t" + $SiteHostname | Out-File -encoding ASCII -append $HostsPath
    }    
}


# iis
Write-Host ""
Write-Host "Setting up IIS" -ForegroundColor Green

Import-Module WebAdministration

# iis: certificate

# iis: app pool
$CreateAppPool = $true

if(Test-Path IIS:\AppPools\$SiteName)
{
    $Confirmation = Read-Host -Prompt "Application Pool already exists... Do you want to overwrite (y/n)?"

    if ($Confirmation -eq 'y') {
        # remove app pool
        Write-Host "Removing app pool..."
        Remove-WebAppPool -Name $SiteName
    } else {
        $CreateAppPool = $false
    }
}

if ($CreateAppPool -eq $true) {
    New-WebAppPool $SiteName
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName=$Username; password=$password; identitytype=3}
}

# iis: set up website
$CreateWebsite = $true
if(Test-Path IIS:\Sites\$SiteName)
{
    $Confirmation = Read-Host -Prompt "IIS Website already exists... Do you want to overwrite (y/n)?"

    if ($Confirmation -eq 'y') {
        # remove app pool
        Write-Host "Removing IIS Website..."
        Remove-WebSite -Name $SiteName
    } else {
        $CreateWebsite = $false
    }
}

if ($CreateWebsite -eq $true) {
    Write-Host "Creating IIS Website..."
    New-WebSite -Name $SiteName -PhysicalPath $Path\$IISWebsiteFolder -ApplicationPool $SiteName -Force
    $IISSite = "IIS:\Sites\$SiteName"
    Set-ItemProperty $IISSite -name  Bindings -value @{protocol="https";bindingInformation="*:443:$SiteHostname"}
    Start-WebSite -Name $SiteName
}


# build website
Write-Host ""
Write-Host "Building Website" -ForegroundColor Green

# npm
Write-Host "Packages Path: $Path\$IISWebsiteFolder\packages.json"

if (Test-Path "$Path\$IISWebsiteFolder\packages.json") {
    Write-Host "npm -> package.json file found... running npm install.."
    Set-Location -Path $Path\$IISWebsiteFolder
    npm install
    Set-Location -Path $Path
}

# nuget packages
if (Test-Path "$Path\$IISWebsiteFolder\packages.config") {    
    Write-Host "nuget -> package.config file found... running nuget restore..."

    # download nuget
    $sourceNugetExe = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
    $targetNugetExe = "$rootPath\nuget.exe"
    Invoke-WebRequest $sourceNugetExe -OutFile $targetNugetExe
    Set-Alias nuget $targetNugetExe -Scope Global -Verbose
    
    #Set-Location -Path $Path\$IISWebsiteFolder
    nuget restore
    #Set-Location -Path $Path
}

# msbuild
Install-Module -Name Invoke-MsBuild 

if ((Invoke-MsBuild "$SolutionFile" -MsBuildParameters "/target:Clean;Build").BuildSucceeded -eq $true)
{
	Write-Output "Build completed successfully."
}


# go back to root
Set-Location -Path $RootPath

# voila
Write-Host ""
Write-Host "Voila!" -ForegroundColor Green

# open in chrome
Start-Process "chrome.exe" "https://$SiteHostname"