<#
.Synopsis
   Find and report configured SPNs and verify computer accounts status and group membership
.DESCRIPTION
   Find and report configured SPNs and verify computer accounts status and group membership
.EXAMPLE
   .\FindSPNs.ps1
.INPUTS
   ReportPathUsersCSV
   If specified, output of SPNs on user accounts will be written to this location/file. If omitted, output will be written to same folder as location of script with predefinied name "FindSPNs.csv".
   
   ReportPathComputersCSV
   If specified, output of SPNs on computer accounts will be written to this location/file. If omitted, output will be written to same folder as location of script with predefinied name "FindSPNs.csv".
   
   NoUsers
   If specified, SPNs from user accounts will not be inventoried
   
   NoComputers
   If specified, SPNs from computer accounts will not be inventoried

   ShowResult
   If specified, results will be shown as it gerts inventoried
.OUTPUTS
   Results will be logged to CSV file and optionally to the console. 
#>

<#
    History
        Date          Version    Description
        2018-12-12    1.0.0      Initial
#>

param
(
    [ValidateNotNull()]
    [ValidateLength(0,2048)]
    $ReportPathUsersCSV     = "$($PSCommandPath | Split-Path -Parent)\SPNUsers.txt",
    
    [ValidateNotNull()]
    [ValidateLength(0,2048)]
    $ReportPathComputersCSV = "$($PSCommandPath | Split-Path -Parent)\SPNComputers.txt",

    [switch]
    $NoUsers,
    
    [switch]
    $NoComputers = $true,

    [switch]
    $showResult
)

$userAccountControlAttributes = @{
    LogonScriptExecuted        = 0x1
    AccountDisabled            = 0x2
    HomeDirRequired            = 0x8
    LockedOut                  = 0x10
    PasswordNotRequired        = 0x20
    CannotChangePassword       = 0x40
    CanSendEncryptedPassword   = 0x80
    DuplicateAccount           = 0x100
    NormalAccount              = 0x200
    TrustAccountForInterDomain = 0x800
    IsComputerAccount          = 0x1000
    ServerTrustAccount         = 0x2000
    PasswordNeverExpires       = 0x10000
    MNSLogonAccount            = 0x20000
    SmartcardRequired          = 0x40000
    TrustedForDelegation       = 0x80000
    NotDelegated               = 0x100000
    UseDESKeyOnly              = 0x200000
    PreAuthNotRequired         = 0x400000
    AccountExpired             = 0x800000
    EnabledForDelegation       = 0x1000000
}

#region Functions
function Log-Text
{
    [cmdletbinding()]
    param
    (
        $Text,
        
        [ValidateSet("Info", "Warning", "Error")]
        $Type = 'Info',
        
        $LogPath = "$($PSCommandPath | Split-Path -Parent)\FindSPNs.log"
    )
    
    Write-Verbose -Message $Text
    
    $timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timeStamp - $($Type.PadRight(10)) - $($Text.Trim())"
    Add-Content -Path $LogPath -Value $logLine
}

function Get-ComputerAccountInfo
{
    param
    (
        $ServicePrincipalName
    )
    
    Write-Verbose -Message "SPNs=$($ServicePrincipalName -join ', ')"

    $result = New-Object psobject -Property @{computerAccountExists=''
                                              NonComputerAccounts=''
                                             }

    $computerAccountExists = @()
    $nonComputerAccounts = @()
    $NamesAlreadyHandled = @()

    $ServicePrincipalName | ForEach-Object `
    {
        $isolatedName = $_.Split('/')[1].Trim("'")
        if ($isolatedName -like '*:*')
        {
            $isolatedName = $isolatedName.Split(':')[0]
        }

        Write-Verbose -Message "  SPN='$isolatedName'"

        if ($NamesAlreadyHandled -notcontains $isolatedName)
        {
            switch ($isolatedName)
            {
                {$_ -match '\.'}
                {
                    $computerAccount = Get-ADComputer -Filter "DNSHostName -eq '$isolatedName'" -Properties lastLogonTimestamp, useraccountcontrol
                
                    if (-not $computerAccount)
                    {
                        Write-Verbose -Message "    Not found: '$isolatedName'"
                        $tryShortName = $isolatedName.split('.')[0]
                        $computerAccount = Get-ADComputer -Filter "Name -eq '$tryShortName'" -Properties lastLogonTimestamp, useraccountcontrol
                        if (-not $computerAccount)
                        {
                            Write-Verbose -Message "    Not found: '$tryShortName'"
                        }
                        else
                        {
                            Write-Verbose -Message "    Success. Found on short name: '$tryShortName'"
                        }
                    }
                }
                default
                {
                    $computerAccount = Get-ADComputer -Filter "Name -eq '$isolatedName'" -Properties lastLogonTimestamp, useraccountcontrol
                }
            }
        
            if ($computerAccount -and ($NamesAlreadyHandled -notcontains $computerAccount.DistinguishedName))
            {
                $computerAccountEnabled = 'Enabled'
                if ($computerAccount.useraccountcontrol -band $userAccountControlAttributes.AccountDisabled)
                {
                    $computerAccountEnabled = 'Disabled'
                }
            
                $ComputerAccountLastLogonTimeStamp = Get-Date ([datetime]::FromFileTime($computerAccount.lastLogonTimestamp)) -Format 'yyyy-MM-dd HH:mm:ss'
            
                $ComputerAccountLastLogonAge = [math]::round(((Get-Date) - (Get-Date ([datetime]::FromFileTime($computerAccount.lastLogonTimestamp)))).TotalDays, 2)
            
                if (((Get-Date) - (Get-Date ([datetime]::FromFileTime($computerAccount.lastLogonTimestamp)))).TotalDays -gt 30)
                {
                    if (-not $ComputerAccountLastLogonTimeStamp.lastLogonTimestamp)
                    {
                        $ComputerAccountLastLogonOver30Days = 'NEVERLOGGEDON'
                    }
                    else
                    {
                        $ComputerAccountLastLogonOver30Days = 'OLD'
                    }
                }
                else
                {
                    $ComputerAccountLastLogonOver30Days = 'Active'
                }
                
                $computerAccountExists += "$isolatedName/$computerAccountEnabled/$ComputerAccountLastLogonOver30Days/$ComputerAccountLastLogonAge/$ComputerAccountLastLogonTimeStamp"
                
                $NamesAlreadyHandled += $isolatedName
            }
            elseif (-not $computerAccount)
            {
                $nonComputerAccounts += $isolatedName
            }
        }
        else
        {
            Write-Verbose -Message "    SPN '$($computerAccount.Name)' already handled"
        }
    }
    
    if ($computerAccountExists)
    {
        $result.computerAccountExists = "'" + $($computerAccountExists -join "', '") + "'"
    }
    else
    {
        $result.computerAccountExists = ''
    }

    if ($nonComputerAccounts)
    {
        $result.nonComputerAccounts = "'" + $($nonComputerAccounts -join "', '") + "'"
    }
    else
    {
        $result.nonComputerAccounts = ''
    }
    
    
    
    Write-Verbose -Message "  computerAccountExists='$($result.computerAccountExists)'"
    Write-Verbose -Message "  NonComputerAccounts='$($result.nonComputerAccounts)'"

    $result
}
#endregion Functions


#region Code
Log-Text -Text 'Start'

$domainSID = (Get-ADDomain).DomainSID
$domainFQDN = (Get-ADDomain).DistinguishedName


if (-not $NoUsers)
{
    #Handle users
    if (Test-Path -Path $ReportPathUsersCSV)
    {
        Remove-Item -Path $ReportPathUsersCSV
    }

    $SPNCount = (Get-ADUser -Filter 'ServicePrincipalNames -like "*"' | Measure-Object).Count
    Write-Verbose -Message "Querying $SPNCount users"
    $idx = 0
     
    Get-ADUser -Filter 'ServicePrincipalNames -like "*"' | Get-ADObject -Properties *, msDS-AllowedToDelegateTo | ForEach-Object `
    {
        $startProcess = Get-Date
        $idx++

        Log-Text -Text "Processing user '$($_.DistinguishedName)"

        $memberOfGroups = @((Get-ADGroup "$domainSID-$($_.primaryGroupID)").DistinguishedName)

        $otherGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($_.name)))")).FindOne()         
        if ($otherGroups)
        {
            $memberOfGroups += $otherGroups.GetDirectoryEntry().memberOf
        }

        
        $computerAccountInfo = Get-ComputerAccountInfo -ServicePrincipalName $_.ServicePrincipalName

        $computerAccountExists              = $computerAccountInfo.computerAccountExists
        $nonComputerAccounts                = $computerAccountInfo.nonComputerAccounts
        
        $record = New-Object pscustomobject -Property @{                      
                                                        Name                              = $_.Name
                                                        SamAccountName                    = $_.SamAccountName
                                                        DistinguishedName                 = $_.DistinguishedName
                                                        SPNs                              = "'" + ($_.ServicePrincipalName -join "', '") + "'"
                                                        Delegations                       = "'" + ($_.'msDS-AllowedToDelegateTo' -join "', '") + "'"
                                                        MemberOfGroups                    = "'" + ($memberOfGroups -join "', '") + "'"
                                                        ComputerAccountExists             = $computerAccountExists
                                                        NonComputerAccounts               = $nonComputerAccounts
                                                        UACLogonScriptExecuted            = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.LogonScriptExecuted) -gt0)
                                                        UACAccountDisabled                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.AccountDisabled) -gt0)
                                                        UACHomeDirRequired                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.HomeDirRequired) -gt0)
                                                        UACLockedOut                      = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.LockedOut) -gt0)
                                                        UACPasswordNotRequired            = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PasswordNotRequired) -gt0)
                                                        UACCannotChangePassword           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.CannotChangePassword) -gt0)
                                                        UACCanSendEncryptedPassword       = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.CanSendEncryptedPassword) -gt0)
                                                        UACDuplicateAccount               = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.DuplicateAccount) -gt0)
                                                        UACNormalAccount                  = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.NormalAccount) -gt0)
                                                        UACTrustAccountForInterDomain     = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.TrustAccountForInterDomain) -gt0)
                                                        UACIsComputerAccount              = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.IsComputerAccount) -gt0)
                                                        UACServerTrustAccount             = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.ServerTrustAccount) -gt0)
                                                        UACPasswordNeverExpires           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PasswordNeverExpires) -gt0)
                                                        UACMNSLogonAccount                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.MNSLogonAccount) -gt0)
                                                        UACSmartcardRequired              = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.SmartcardRequired) -gt0)
                                                        UACTrustedForDelegation           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.TrustedForDelegation) -gt0)
                                                        UACNotDelegated                   = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.NotDelegated) -gt0)
                                                        UACUseDESKeyOnly                  = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.UseDESKeyOnly) -gt0)
                                                        UACPreAuthNotRequired             = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PreAuthNotRequired) -gt0)
                                                        UACAccountExpired                 = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.AccountExpired) -gt0)
                                                        UACEnabledForDelegation           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.EnabledForDelegation) -gt0)
                                                       }
    
        $record | Select-Object -Property Name, `
                                          SamAccountName, `
                                          DistinguishedName, `
                                          SPNs, `
                                          Delegations, `
                                          MemberOfGroups, `
                                          ComputerAccountExists, `
                                          NonComputerAccounts, `
                                          @{n='UACLogonScriptExecuted';e={if ($_.UACLogonScriptExecuted) {'1'}}}, `
                                          @{n='UACAccountDisabled';e={if ($_.UACAccountDisabled) {'1'}}}, `
                                          @{n='UACHomeDirRequired';e={if ($_.UACHomeDirRequired) {'1'}}}, `
                                          @{n='UACLockedOut';e={if ($_.UACLockedOut) {'1'}}}, `
                                          @{n='UACPasswordNotRequired';e={if ($_.UACPasswordNotRequired) {'1'}}}, `
                                          @{n='UACCannotChangePassword';e={if ($_.UACCannotChangePassword) {'1'}}}, `
                                          @{n='UACCanSendEncryptedPassword';e={if ($_.UACCanSendEncryptedPassword) {'1'}}}, `
                                          @{n='UACDuplicateAccount';e={if ($_.UACDuplicateAccount) {'1'}}}, `
                                          @{n='UACNormalAccount';e={if ($_.UACNormalAccount) {'1'}}}, `
                                          @{n='UACTrustAccountForInterDomain';e={if ($_.UACTrustAccountForInterDomain) {'1'}}}, `
                                          @{n='UACIsComputerAccount';e={if ($_.UACIsComputerAccount) {'1'}}}, `
                                          @{n='UACServerTrustAccount';e={if ($_.UACServerTrustAccount) {'1'}}}, `
                                          @{n='UACPasswordNeverExpires';e={if ($_.UACPasswordNeverExpires) {'1'}}}, `
                                          @{n='UACMNSLogonAccount';e={if ($_.UACMNSLogonAccount) {'1'}}}, `
                                          @{n='UACSmartcardRequired';e={if ($_.UACSmartcardRequired) {'1'}}}, `
                                          @{n='UACTrustedForDelegation';e={if ($_.UACTrustedForDelegation) {'1'}}}, `
                                          @{n='UACNotDelegated';e={if ($_.UACNotDelegated) {'1'}}}, `
                                          @{n='UACUseDESKeyOnly';e={if ($_.UACUseDESKeyOnly) {'1'}}}, `
                                          @{n='UACPreAuthNotRequired';e={if ($_.UACPreAuthNotRequired) {'1'}}}, `
                                          @{n='UACAccountExpired';e={if ($_.UACAccountExpired) {'1'}}}, `
                                          @{n='UACEnabledForDelegation';e={if ($_.UACEnabledForDelegation) {'1'}}} | Export-Csv -Path $ReportPathUsersCSV -Append -NoTypeInformation -Encoding UTF8
        
        if ($showResult)
        {
            $record | Select-Object -Property Name, `
                                              DistinguishedName, `
                                              SPNs, `
                                              Delegations, `
                                              MemberOfGroups, `
                                              ComputerAccountExists, `
                                              NonComputerAccounts, `
                                              @{n='UACLogonScriptExecuted';e={if ($_.UACLogonScriptExecuted) {'1'}}}, `
                                              @{n='UACAccountDisabled';e={if ($_.UACAccountDisabled) {'1'}}}, `
                                              @{n='UACHomeDirRequired';e={if ($_.UACHomeDirRequired) {'1'}}}, `
                                              @{n='UACLockedOut';e={if ($_.UACLockedOut) {'1'}}}, `
                                              @{n='UACPasswordNotRequired';e={if ($_.UACPasswordNotRequired) {'1'}}}, `
                                              @{n='UACCannotChangePassword';e={if ($_.UACCannotChangePassword) {'1'}}}, `
                                              @{n='UACCanSendEncryptedPassword';e={if ($_.UACCanSendEncryptedPassword) {'1'}}}, `
                                              @{n='UACDuplicateAccount';e={if ($_.UACDuplicateAccount) {'1'}}}, `
                                              @{n='UACNormalAccount';e={if ($_.UACNormalAccount) {'1'}}}, `
                                              @{n='UACTrustAccountForInterDomain';e={if ($_.UACTrustAccountForInterDomain) {'1'}}}, `
                                              @{n='UACIsComputerAccount';e={if ($_.UACIsComputerAccount) {'1'}}}, `
                                              @{n='UACServerTrustAccount';e={if ($_.UACServerTrustAccount) {'1'}}}, `
                                              @{n='UACPasswordNeverExpires';e={if ($_.UACPasswordNeverExpires) {'1'}}}, `
                                              @{n='UACMNSLogonAccount';e={if ($_.UACMNSLogonAccount) {'1'}}}, `
                                              @{n='UACSmartcardRequired';e={if ($_.UACSmartcardRequired) {'1'}}}, `
                                              @{n='UACTrustedForDelegation';e={if ($_.UACTrustedForDelegation) {'1'}}}, `
                                              @{n='UACNotDelegated';e={if ($_.UACNotDelegated) {'1'}}}, `
                                              @{n='UACUseDESKeyOnly';e={if ($_.UACUseDESKeyOnly) {'1'}}}, `
                                              @{n='UACPreAuthNotRequired';e={if ($_.UACPreAuthNotRequired) {'1'}}}, `
                                              @{n='UACAccountExpired';e={if ($_.UACAccountExpired) {'1'}}}, `
                                              @{n='UACEnabledForDelegation';e={if ($_.UACEnabledForDelegation) {'1'}}} 
        }
        else
        {
            $_.Name
        }

        Write-Verbose -Message "$idx/$SPNCount - Time taken: $(((Get-Date)-$startProcess).TotalSeconds) seconds"
    }
}


if (-not $NoComputers)
{
    #Handle computers
    if (Test-Path -Path $ReportPathComputersCSV)
    {
        Remove-Item -Path $ReportPathComputersCSV
    }

    $SPNCount = (Get-ADUser -Filter 'ServicePrincipalNames -like "*"' | Measure-Object).Count
    Write-Verbose -Message "Querying $SPNCount computers"
    $idx = 0
    
    Get-ADComputer -Filter 'ServicePrincipalNames -like "*"' | Get-ADObject -Properties *, msDS-AllowedToDelegateTo | ForEach-Object `
    {
        $startProcess = Get-Date
        $idx++

        Log-Text -Text "Processing user '$($_.DistinguishedName)"

        $memberOfGroups = @((Get-ADGroup "$domainSID-$($_.primaryGroupID)").DistinguishedName)

        $otherGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($_.name)$))")).FindOne()         
        if ($otherGroups)
        {
            $memberOfGroups += $otherGroups.GetDirectoryEntry().memberOf
        }

        
        $computerAccountInfo = Get-ComputerAccountInfo -ServicePrincipalName $_.ServicePrincipalName

        $computerAccountExists              = $computerAccountInfo.computerAccountExists
        $nonComputerAccounts                = $computerAccountInfo.nonComputerAccounts
        
        $record = New-Object pscustomobject -Property @{                      
                                                        Name                              = $_.Name
                                                        SamAccountName                    = $_.SamAccountName
                                                        DistinguishedName                 = $_.DistinguishedName
                                                        SPNs                              = "'" + ($_.ServicePrincipalName -join "', '") + "'"
                                                        Delegations                       = "'" + ($_.'msDS-AllowedToDelegateTo' -join "', '") + "'"
                                                        MemberOfGroups                    = "'" + ($memberOfGroups -join "', '") + "'"
                                                        ComputerAccountExists             = $computerAccountExists
                                                        NonComputerAccounts               = $nonComputerAccounts
                                                        UACLogonScriptExecuted            = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.LogonScriptExecuted) -gt0)
                                                        UACAccountDisabled                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.AccountDisabled) -gt0)
                                                        UACHomeDirRequired                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.HomeDirRequired) -gt0)
                                                        UACLockedOut                      = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.LockedOut) -gt0)
                                                        UACPasswordNotRequired            = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PasswordNotRequired) -gt0)
                                                        UACCannotChangePassword           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.CannotChangePassword) -gt0)
                                                        UACCanSendEncryptedPassword       = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.CanSendEncryptedPassword) -gt0)
                                                        UACDuplicateAccount               = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.DuplicateAccount) -gt0)
                                                        UACNormalAccount                  = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.NormalAccount) -gt0)
                                                        UACTrustAccountForInterDomain     = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.TrustAccountForInterDomain) -gt0)
                                                        UACIsComputerAccount              = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.IsComputerAccount) -gt0)
                                                        UACServerTrustAccount             = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.ServerTrustAccount) -gt0)
                                                        UACPasswordNeverExpires           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PasswordNeverExpires) -gt0)
                                                        UACMNSLogonAccount                = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.MNSLogonAccount) -gt0)
                                                        UACSmartcardRequired              = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.SmartcardRequired) -gt0)
                                                        UACTrustedForDelegation           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.TrustedForDelegation) -gt0)
                                                        UACNotDelegated                   = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.NotDelegated) -gt0)
                                                        UACUseDESKeyOnly                  = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.UseDESKeyOnly) -gt0)
                                                        UACPreAuthNotRequired             = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.PreAuthNotRequired) -gt0)
                                                        UACAccountExpired                 = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.AccountExpired) -gt0)
                                                        UACEnabledForDelegation           = [int](([int64]$_.UserAccountControl -band $userAccountControlAttributes.EnabledForDelegation) -gt0)
                                                       }
    
        $record | Select-Object -Property Name, `
                                          SamAccountName, `
                                          DistinguishedName, `
                                          SPNs, `
                                          Delegations, `
                                          MemberOfGroups, `
                                          ComputerAccountExists, `
                                          NonComputerAccounts, `
                                          @{n='UACLogonScriptExecuted';e={if ($_.UACLogonScriptExecuted) {'1'}}}, `
                                          @{n='UACAccountDisabled';e={if ($_.UACAccountDisabled) {'1'}}}, `
                                          @{n='UACHomeDirRequired';e={if ($_.UACHomeDirRequired) {'1'}}}, `
                                          @{n='UACLockedOut';e={if ($_.UACLockedOut) {'1'}}}, `
                                          @{n='UACPasswordNotRequired';e={if ($_.UACPasswordNotRequired) {'1'}}}, `
                                          @{n='UACCannotChangePassword';e={if ($_.UACCannotChangePassword) {'1'}}}, `
                                          @{n='UACCanSendEncryptedPassword';e={if ($_.UACCanSendEncryptedPassword) {'1'}}}, `
                                          @{n='UACDuplicateAccount';e={if ($_.UACDuplicateAccount) {'1'}}}, `
                                          @{n='UACNormalAccount';e={if ($_.UACNormalAccount) {'1'}}}, `
                                          @{n='UACTrustAccountForInterDomain';e={if ($_.UACTrustAccountForInterDomain) {'1'}}}, `
                                          @{n='UACIsComputerAccount';e={if ($_.UACIsComputerAccount) {'1'}}}, `
                                          @{n='UACServerTrustAccount';e={if ($_.UACServerTrustAccount) {'1'}}}, `
                                          @{n='UACPasswordNeverExpires';e={if ($_.UACPasswordNeverExpires) {'1'}}}, `
                                          @{n='UACMNSLogonAccount';e={if ($_.UACMNSLogonAccount) {'1'}}}, `
                                          @{n='UACSmartcardRequired';e={if ($_.UACSmartcardRequired) {'1'}}}, `
                                          @{n='UACTrustedForDelegation';e={if ($_.UACTrustedForDelegation) {'1'}}}, `
                                          @{n='UACNotDelegated';e={if ($_.UACNotDelegated) {'1'}}}, `
                                          @{n='UACUseDESKeyOnly';e={if ($_.UACUseDESKeyOnly) {'1'}}}, `
                                          @{n='UACPreAuthNotRequired';e={if ($_.UACPreAuthNotRequired) {'1'}}}, `
                                          @{n='UACAccountExpired';e={if ($_.UACAccountExpired) {'1'}}}, `
                                          @{n='UACEnabledForDelegation';e={if ($_.UACEnabledForDelegation) {'1'}}} | Export-Csv -Path $ReportPathUsersCSV -Append -NoTypeInformation -Encoding UTF8
        
        if ($showResult)
        {
            $record | Select-Object -Property Name, `
                                              DistinguishedName, `
                                              SPNs, `
                                              Delegations, `
                                              MemberOfGroups, `
                                              ComputerAccountExists, `
                                              NonComputerAccounts, `
                                              @{n='UACLogonScriptExecuted';e={if ($_.UACLogonScriptExecuted) {'1'}}}, `
                                              @{n='UACAccountDisabled';e={if ($_.UACAccountDisabled) {'1'}}}, `
                                              @{n='UACHomeDirRequired';e={if ($_.UACHomeDirRequired) {'1'}}}, `
                                              @{n='UACLockedOut';e={if ($_.UACLockedOut) {'1'}}}, `
                                              @{n='UACPasswordNotRequired';e={if ($_.UACPasswordNotRequired) {'1'}}}, `
                                              @{n='UACCannotChangePassword';e={if ($_.UACCannotChangePassword) {'1'}}}, `
                                              @{n='UACCanSendEncryptedPassword';e={if ($_.UACCanSendEncryptedPassword) {'1'}}}, `
                                              @{n='UACDuplicateAccount';e={if ($_.UACDuplicateAccount) {'1'}}}, `
                                              @{n='UACNormalAccount';e={if ($_.UACNormalAccount) {'1'}}}, `
                                              @{n='UACTrustAccountForInterDomain';e={if ($_.UACTrustAccountForInterDomain) {'1'}}}, `
                                              @{n='UACIsComputerAccount';e={if ($_.UACIsComputerAccount) {'1'}}}, `
                                              @{n='UACServerTrustAccount';e={if ($_.UACServerTrustAccount) {'1'}}}, `
                                              @{n='UACPasswordNeverExpires';e={if ($_.UACPasswordNeverExpires) {'1'}}}, `
                                              @{n='UACMNSLogonAccount';e={if ($_.UACMNSLogonAccount) {'1'}}}, `
                                              @{n='UACSmartcardRequired';e={if ($_.UACSmartcardRequired) {'1'}}}, `
                                              @{n='UACTrustedForDelegation';e={if ($_.UACTrustedForDelegation) {'1'}}}, `
                                              @{n='UACNotDelegated';e={if ($_.UACNotDelegated) {'1'}}}, `
                                              @{n='UACUseDESKeyOnly';e={if ($_.UACUseDESKeyOnly) {'1'}}}, `
                                              @{n='UACPreAuthNotRequired';e={if ($_.UACPreAuthNotRequired) {'1'}}}, `
                                              @{n='UACAccountExpired';e={if ($_.UACAccountExpired) {'1'}}}, `
                                              @{n='UACEnabledForDelegation';e={if ($_.UACEnabledForDelegation) {'1'}}} 
        }
        else
        {
            $_.Name
        }

        Write-Verbose -Message "$idx/$SPNCount - Time taken: $(((Get-Date)-$startProcess).TotalSeconds) seconds"
    }
}

#endregion Code

Log-Text -Text 'Finish'
Log-Text -Text '------------------------------------------------------------------------------------------------------------------------------'
