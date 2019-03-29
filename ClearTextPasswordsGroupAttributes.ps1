
 
Function RevealClearTextPassword(){
<#
.SYNOPSIS
Finder alle brugerkonti i AD, hvor Description eller Info feltet indeholder et af de angivne søgeord
.DESCRIPTION
Finder alle brugerkonti i AD, hvor Description eller Info feltet indeholder et af de angivne søgeord
  .EXAMPLE
RevealClearTextPassword pwd,pass,pw,kode
  Ovenstående henter alle brugerobjekter, hvor pwd, pass, pw eller kode indgår som en del af teksten i Description eller Info feltet `n
HUSK! Der søges også på mellemrum. pwd,pass,pw,kode og pwd, pass , pw, kode er derfor to forskellige søgninger.
  .EXAMPLE
RevealClearTextPassword pwd,pass,pw,kode ad.lokal
  Ovenstående henter alle brugerobjekter, i AD.LOKAL, hvor pwd, pass, pw eller kode indgår som en del af teksten i Description eller Info feltet `n
HUSK! Der søges også på mellemrum. pwd,pass,pw,kode og pwd, pass , pw, kode er derfor to forskellige søgninger.
  .EXAMPLE
RevealClearTextPassword -Search pwd,pass,pw,kode -Domain ad.lokal
  Ovenstående henter alle brugerobjekter, i AD.LOKAL, hvor pwd, pass, pw eller kode indgår som en del af teksten i Description eller Info feltet `n
HUSK! Der søges også på mellemrum. pwd,pass,pw,kode og pwd, pass , pw, kode er derfor to forskellige søgninger.
.PARAMETER Search
De ord eller bogstavkombinationer der skal søges på
#>
 
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True,Position=1)]
		[Array]$Search,
 
		[Parameter(Mandatory=$False,Position=2)]
		[String]$Domain
	)
 
	$words = $search -split ","
	$dc = ""
 
	IF($Domain -ne ""){
		$domaininfo = Get-ADDomain $Domain
		$dcName = $domaininfo.RIDMaster
	}
	ELSE{
		$dcName = (Get-ADDomain).RIDMaster
	}
 
	foreach($word in $words){
 
		$list = $list += "(`$_.info -like `"*$word*`") -OR "
	}
 
	$list = $list.substring(0,$list.Length-5)
	# Use the line below to filter certain entries if need be
	# $list = $list += "-and (`$_.Description -notlike `"*searchTerm*`") -and (`$_.Description -notlike `"*otherSearchTerm*`")"

	#Get-ADGroup -filter * -server $dcName -Properties Description, Info | Where{Invoke-Expression $list} | select samaccountname,description,info | Out-GridView

	Get-ADGroup -filter * -server $dcName -Properties Description, Info | Where{Invoke-Expression $list} | select samaccountname,description,info | fl | Out-File "RevealClearTextPwdsInAD_groups.txt"
}


RevealClearTextPassword -Search pwd,pass,pw,kodeord #-Domain "Replace With Domain Name if not the one of the current user"

