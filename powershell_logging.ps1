########## AS_W_01 ##########
# Audit Success Process Creation event

auditpol /set /category:"detailed tracking" /subcategory:"Process Creation" /success:enable | Out-Null

########## AS_W_02 ##########
# Include command line in process creation events

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$Name = "ProcessCreationIncludeCmdLine_Enabled"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

########## AS_W_03 ##########
# Turn on Module Logging

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$Name = "EnableModuleLogging"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
$Name = "*"
$value = "*"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
}

########## AS_W_04 ##########
# Configure script block logging for PowerShell

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$Name = "EnableScriptBlockLogging"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$Name = "EnableScriptBlockInvocationLogging"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

########## AS_W_05 ##########
# Turn on PowerShell Transcript

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
$Name = "EnableInvocationHeader"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
$Name = "EnableTranscripting"
$value = "1"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

$registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
$Name = "OutputDirectory"
#$value = "C:\pstrans\"
$value = "C:\Cursos\CyberSecurity\ModernEthicalHacking\Downloads\"

IF (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
} ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
}

########## AS_W_06 ##########
# Create and Secure Folder C:\pstrans for PowerShell Transcript

#$value = "C:\pstrans"
$value = "C:\Cursos\CyberSecurity\ModernEthicalHacking\Downloads"

# Creating a new directory if it doesn't exist
New-Item -ItemType directory -Force -Path $value | Out-Null

# Getting the ACL for the directory
$acl = Get-ACL -Path $value

# Setting the ACL to protect the access rules
$acl.SetAccessRuleProtection($true,$false)

# Create access rule for BUILTIN\Administrators using Well-Known SID
$BuiltInAdminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")  # BUILTIN\Administrators SID
$AccessRuleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltInAdminsSID,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRuleAdmins)

# Create access rule for NT AUTHORITY\SYSTEM using Well-Known SID
$SystemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")  # NT AUTHORITY\SYSTEM SID
$AccessRuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule($SystemSID,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRuleSystem)

# Apply the modified ACL to the directory
$acl | Set-Acl $value
