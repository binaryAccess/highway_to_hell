param(
    [string] $Domain
)

Function SearchGroupClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADGroup -Filter * -Server $dc -Properties Description,Info |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Description,Info | 
        fl
}

SearchGroupClearTextInformation -Terms @("pwd", "pass", "pw", "kodeord") @PSBoundParameters
