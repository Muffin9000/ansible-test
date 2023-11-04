# GET ROOT DOMAIN OU
$rootDSE = (Get-ADRootDSE).rootDomainNamingContext
# Path to Sysvol
$smbSysvol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

# Root of all Member Server Resources
$resRoot = "Servers"
$resourceOU = "OU=$($resRoot),$($rootDSE)"

$getMSRoot=@()
$getMSRoot = Get-ADOrganizationalUnit -filter * | where {$_.DistinguishedName -eq $resourceOU }

# Admin Group
$rgRtAdminGp = "Local Admin"
$rgRtAdminDescrip = "Local Administrators for Servers in Servers OU"
New-ADGroup -Name $rgRtAdminGp -groupscope "Global" -Description $rgRtAdminDescrip

# Get New Group Name and SID
$getRtRGAdmin = Get-ADGroup $rgRtAdminGp
$getRtRGAdminSid = $getRtRGAdmin.SID.Value

# New GPO based on the service and linked to OU
$GPOName = "Local Admin"
New-GPO -Name $GPOName | New-GPLink -Target $getMSRoot.DistinguishedName

$getGpoId = (Get-GPO $GPOName).id
$getGPOPath = (Get-GPO $GPOName).path

Set-GPPermission -Guid $getGpoId -PermissionLevel GpoEditDeleteModifySecurity -TargetType Group -TargetName $rgRtAdminGp
$sysvol = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\Machine\Microsoft\Windows NT\SecEdit"

$gpt = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\GPT.ini"
Set-content $gpt -Value "[General]"
Add-Content $gpt -Value "Version=1" 

New-Item -Path $sysvol -ItemType Directory -Force
New-Item -Path $sysvol -Name GptTmpl.inf -ItemType File -Force

$gptFile = "$($sysvol)\GptTmpl.inf"

# S-1-5-32-544 = Administrators Group

# Update GmpTmpl.inf with Restricted Groups
Add-Content -Path $gptFile -Value '[Unicode]'
Add-Content -Path $gptFile -Value 'Unicode=yes'
Add-Content -Path $gptFile -Value '[Version]'
Add-Content -Path $gptFile -Value 'signature="$CHICAGO$"'
Add-Content -Path $gptFile -Value 'Revision=1'
Add-Content -Path $gptFile -Value '[Group Membership]'
Add-Content -Path $gptFile -Value "*$($getRtRGAdminSid)__Memberof = *S-1-5-32-544"
Add-Content -Path $gptFile -Value "*$($getRtRGAdminSid)__Members ="

# Set GPMC Machine Extensions so Manual Intervention is both displayed in GPO Management and applies to target 
Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}
Set-ADObject -Identity $getGPOPath -Replace @{versionNumber="1"}

$owboostUsersOUPath = "OU=OWBOOST,$($rootDSE)"
$rdpGroupName = "MSTSC"
$doaminAdminGroup = "Domain Admins" 

# Get all users in the specified OU
$ouUsers = Get-ADUser -Filter * -SearchBase $owboostUsersOUPath

# Initialize an array to store users who are members of the RDP group
$rdpGroupMembers = @()

# Add users to local admin if they are a member of MSTSC but no Domain Admin
foreach ($user in $ouUsers) {
    if ((Get-ADPrincipalGroupMembership $user | Where-Object { $_.Name -eq $rdpGroupName }) -and !(Get-ADPrincipalGroupMembership $user | Where-Object { $_.Name -eq $doaminAdminGroup })) {
        Add-ADGroupMember -Identity $rgRtAdminGp -Members $user
    }
}
