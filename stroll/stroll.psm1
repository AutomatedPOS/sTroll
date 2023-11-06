#region Classes
class Checklist{
    [string]$stigid
    [string]$title
    [string]$version
    [string]$release
    [System.IO.FileSystemInfo]$FileInfo
    [System.Xml.XmlNode]$xml
    [string]$hash
    [string]$uniqueID
    [string]$HOST_NAME
    [string]$WEB_DB_INSTANCE
    [string]$WEB_DB_SITE
    [string]$ROLE
    [string]$TECH_AREA
    [string]$WEB_OR_DATABASE
    [string]$HOST_IP
    [string]$HOST_MAC
    [string]$HOST_FQDN
    [string]$TARGET_COMMENT
    [string]$AssetType
    [System.Collections.ArrayList]$VULNS = @()

    Checklist([string]$pathToChecklist){
        $this.FileInfo = Get-ChildItem -Path $pathToChecklist
        $this.xml = (Select-Xml -Path $this.FileInfo.FullName -XPath /).node
        $this.stigid = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("stigid")]
        $this.title = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("title")]
        $this.version = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("version")]
        $this.release = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("releaseinfo")]
        $this.AssetType = $this.xml.CHECKLIST.ASSET.ASSET_TYPE
        $this.release = $this.release.Replace("Release: ","")
        $this.release = $this.release -replace " Benc.*",""
        $this.HOST_NAME = $this.xml.CHECKLIST.ASSET.HOST_NAME.ToUpper()
        $this.HOST_IP = $this.xml.CHECKLIST.ASSET.HOST_IP
        $this.HOST_MAC = $this.xml.CHECKLIST.ASSET.HOST_MAC.ToUpper()
        $this.HOST_FQDN = $this.xml.CHECKLIST.ASSET.HOST_FQDN.ToUpper()
        $this.WEB_OR_DATABASE = $this.xml.CHECKLIST.ASSET.WEB_OR_DATABASE.ToLower()
        $this.WEB_DB_INSTANCE = $this.xml.CHECKLIST.ASSET.WEB_DB_INSTANCE.ToUpper()
        $this.WEB_DB_SITE = $this.xml.CHECKLIST.ASSET.WEB_DB_SITE.ToUpper()
        $this.uniqueID = $this.HOST_NAME +"_"+ $this.stigid +"_"+ $this.WEB_DB_INSTANCE +"_" + $this.WEB_DB_SITE
        $this.ROLE = $this.xml.CHECKLIST.ASSET.ROLE
        $this.TECH_AREA = $this.xml.CHECKLIST.ASSET.TECH_AREA
        $this.TARGET_COMMENT = $this.xml.CHECKLIST.ASSET.TARGET_COMMENT
    }
    
    Checklist([System.Xml.XmlNode]$xmlData){
        $this.FileInfo = $null
        $this.xml = $xmlData
        $this.stigid = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("stigid")]
        $this.title = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("title")]
        $this.version = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("version")]
        $this.release = $this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_DATA[$this.xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.SID_NAME.IndexOf("releaseinfo")]
        $this.release = $this.release.Replace("Release: ","")
        $this.release = $this.release -replace " Benc.*",""
        $this.AssetType = $this.xml.CHECKLIST.ASSET.ASSET_TYPE
        $this.HOST_NAME = $this.xml.CHECKLIST.ASSET.HOST_NAME.ToUpper()
        $this.HOST_IP = $this.xml.CHECKLIST.ASSET.HOST_IP
        $this.HOST_MAC = $this.xml.CHECKLIST.ASSET.HOST_MAC.ToUpper()
        $this.HOST_FQDN = $this.xml.CHECKLIST.ASSET.HOST_FQDN.ToUpper()
        $this.WEB_OR_DATABASE = $this.xml.CHECKLIST.ASSET.WEB_OR_DATABASE.ToLower()
        $this.WEB_DB_INSTANCE = $this.xml.CHECKLIST.ASSET.WEB_DB_INSTANCE.ToUpper()
        $this.WEB_DB_SITE = $this.xml.CHECKLIST.ASSET.WEB_DB_SITE.ToUpper()
        $this.uniqueID = $this.HOST_NAME +"_"+ $this.stigid +"_"+ $this.WEB_DB_INSTANCE +"_" + $this.WEB_DB_SITE
        $this.ROLE = $this.xml.CHECKLIST.ASSET.ROLE
        $this.TECH_AREA = $this.xml.CHECKLIST.ASSET.TECH_AREA
        $this.TARGET_COMMENT = $this.xml.CHECKLIST.ASSET.TARGET_COMMENT
    }

    [void] SetAssetInfo(){
        $this.SetHOSTNAME()
        $this.SetAssetType()
        $this.SetIP()
        $this.SetFQDN()
        $this.SetMAC()
        $this.SetROLE()
        $this.SetTechArea()
        $this.SetWDB()
        $this.SetDB()
        $this.SetInstance()
        $this.SetTargetComment()
    }
    [void] SetHOSTNAME(){
        $this.xml.CHECKLIST.ASSET.HOST_NAME = $this.HOST_NAME
    }
    [void] SetAssetType(){
        $this.xml.CHECKLIST.ASSET.ASSET_TYPE = $this.AssetType
    }
    [void] SetIP(){
        $this.xml.CHECKLIST.ASSET.HOST_IP = $this.HOST_IP
    }
    [void] SetFQDN(){
        $this.xml.CHECKLIST.ASSET.HOST_FQDN = $this.HOST_FQDN.ToUpper()
    }
    [void] SetMAC(){
        $this.xml.CHECKLIST.ASSET.HOST_MAC = $this.HOST_MAC.ToUpper()
    }
    [void] SetROLE(){
        $this.xml.CHECKLIST.ASSET.ROLE = $this.ROLE
    }
    [void] SetTechArea(){
        $this.xml.CHECKLIST.ASSET.TECH_AREA = $this.TECH_AREA
    }
    [void] SetWDB(){
        $this.xml.CHECKLIST.ASSET.WEB_OR_DATABASE = $this.WEB_OR_DATABASE
    }
    [void] SetDB(){
        $this.xml.CHECKLIST.ASSET.WEB_DB_SITE = $this.WEB_DB_SITE
    }
    [void] SetInstance(){
        $this.xml.CHECKLIST.ASSET.WEB_DB_INSTANCE = $this.WEB_DB_INSTANCE
    }
    [void] SetTargetComment(){
        $this.xml.CHECKLIST.ASSET.TARGET_COMMENT = $this.TARGET_COMMENT
    }
    [void] EmptyXML(){
        $this.xml.RemoveAll()
    }
    [void] AnalyzeVulnsCCRI([System.Array]$SeverityOverrides){
        $this.VULNS =@()
        ForEach($lclVuln in $this.xml.CHECKLIST.STIGS.iSTIG.VULN){
            [Vulnerability]$newVuln = [Vulnerability]::new($lclVuln)
            if($SeverityOverrides.VulnID.ToUpper() -contains $newVuln.VulnID.ToUpper()){
                $newVuln.SetOverride()
                $lclIndex = $SeverityOverrides.VulnID.ToUpper().IndexOf($newVuln.VulnID.ToUpper())
                $newVuln.SetKIORSection($SeverityOverrides[$lclIndex].KIoRSection)
                $newVuln.SetKIORSubSection($SeverityOverrides[$lclIndex].KIoRSubSection)

            }
            $this.VULNS.Add($newVuln)
        }
    }
    [void] AnalyzeVulns(){
        $this.VULNS =@()
        ForEach($lclVuln in $this.xml.CHECKLIST.STIGS.iSTIG.VULN){
            [Vulnerability]$newVuln = [Vulnerability]::new($lclVuln)
            $this.VULNS.Add($newVuln)
        }
    }
}

class SCCXCCDF{
    [string]$stigid
    [string]$title
    [string]$version
    [string]$release
    [System.IO.FileSystemInfo]$FileInfo
    [System.Xml.XmlNode]$xml
    [string]$hash
    [string]$uniqueID
    [string]$HOST_NAME
    [string]$WEB_DB_INSTANCE
    [string]$WEB_DB_SITE
    [string]$ROLE
    [string]$TECH_AREA
    [string]$WEB_OR_DATABASE
    [string]$HOST_IP
    [string]$HOST_MAC
    [string]$HOST_FQDN
    [string]$TARGET_COMMENT
    [string]$AssetType
    [System.Collections.ArrayList]$VULNS = @()

    SCCXCCDF([string]$pathToXCCDF){
        $this.FileInfo = Get-ChildItem -Path $pathToXCCDF
        $this.xml = (Select-Xml -Path $this.FileInfo.FullName -XPath /).node
        $this.stigid = $this.xml.Benchmark.id -replace ".*benchmark_",""
        $this.title = $this.xml.Benchmark.title
        $this.version = $this.xml.Benchmark.version.'#text' -replace "\..*",""
        $this.release = $this.xml.Benchmark.version.'#text' -replace ".*\.",""
        $this.AssetType = ""
        $this.HOST_NAME = ($this.xml.Benchmark.TestResult.target).ToUpper()
        $this.HOST_IP = $this.xml.Benchmark.TestResult.'target-address'[0]
        $this.HOST_MAC = $this.xml.Benchmark.TestResult.'target-facts'.fact.'#text'[$this.xml.Benchmark.TestResult.'target-facts'.fact.name.IndexOf("urn:scap:fact:asset:identifier:mac")]
        $this.HOST_FQDN = $this.xml.Benchmark.TestResult.'target-facts'.fact.'#text'[$this.xml.Benchmark.TestResult.'target-facts'.fact.name.IndexOf("urn:scap:fact:asset:identifier:fqdn")]
        $this.uniqueID = $this.HOST_NAME +"_"+ $this.stigid +"_"+ $this.WEB_DB_INSTANCE +"_" + $this.WEB_DB_SITE
    }
    [void] AnalyzeVulns(){
        $this.VULNS =@()
        ForEach($lclVuln in $this.xml.Benchmark.TestResult.'rule-result'){
            $lclVulnID = ($lclVuln.idref -replace ".*stig_rule_S","") -replace "r.*"
            $lclRuleID = $lclVuln.idref -replace ".*stig_rule_",""
            $lclStatus = ""
            if($lclVuln.result -eq "pass"){
                $lclStatus = "NotAFinding"
            }
            elseif ($lclVuln.result -eq "fail") {
                $lclStatus = "Open"
            }
            elseif ($lclVuln.result -eq "notapplicable"){
                $lclStatus = "Not_Applicable"
            }

            $lclFindingDetails = $lclVuln.message.'#text'

            if($lclStatus -eq ""){
                #do nothing?
            }
            else{
                [Vulnerability]$newVuln = [Vulnerability]::new($lclVulnID,$lclStatus,$lclFindingDetails,$lclRuleID)
                $this.VULNS.Add($newVuln)
            }
            Remove-Variable lclVuln,lclRuleID,lclStatus,lclFindingDetails

        }
    }
}

class Vulnerability{
    [string]$VulnID
    [string]$Status
    [string]$FindingDetails
    [string]$Comments
    [string]$Severity
    [string]$RuleID
    [switch]$CCRIOverride
    [string]$KIoRSection
    [string]$KIoRSubSection
    [double]$points

    Vulnerability(){
        #basic constructer
    }
    Vulnerability([System.Xml.XmlElement]$VulnXML){
        $this.VulnID = $VulnXML.STIG_DATA.ATTRIBUTE_DATA[$VulnXML.STIG_DATA.VULN_ATTRIBUTE.IndexOf("Vuln_Num")]
        $this.Comments = $VulnXML.COMMENTS
        $this.Status = $VulnXML.STATUS
        $this.FindingDetails = $VulnXML.FINDING_DETAILS
        $this.Severity = $VulnXML.STIG_DATA.ATTRIBUTE_DATA[$VulnXML.STIG_DATA.VULN_ATTRIBUTE.IndexOf("Severity")]
        $this.RuleID = $VulnXML.STIG_DATA.ATTRIBUTE_DATA[$VulnXML.STIG_DATA.VULN_ATTRIBUTE.IndexOf("Rule_ID")]
        $this.points = 0
    }

    Vulnerability([string]$xVulnID,[string]$xStatus,[string]$xFindingDetails,[string]$xRuleID){
        $this.VulnID = $xVulnID
        $this.Status = $xStatus
        $this.FindingDetails = $xFindingDetails
        $this.RuleID = $xRuleID
    }

    [void] SetOverride(){
        $this.CCRIOverride = $true
    }
    [void] SetKIORSection([string]$KioR){
        $this.KIoRSection = $KioR
    }
    [void] SetKIORSubSection([string]$KioR){
        $this.KIoRSubSection = $KioR
    }
    [void] SetPOINTS([double]$PointSet){
        $this.points = $PointSet
    }
}
#endregion

#region Functions
function Import-Checklist {
    <#
    .SYNOPSIS
        Copies checklist data (host information and/or finding results) from one Checklist File to another.
        
    .DESCRIPTION
        Can be used to upgrade checklists to later versions / releases.  Import-checklist will copy data from a one checklist file to another.
    
    .PARAMETER SourceCKL
        Path to the Source Checklist file (.ckl) that will be used within the import.

    .PARAMETER DestinationCKL
        Path to the destination Checklist file (.ckl) that will be used within the import.

    .PARAMETER MatchON
        Default - RuleID
        Sets how this function will perform matching/
        RuleID means findings will be matched by RULEID value (Most Accurate / Most Stringent)
        VulnID means findings will be matched by VULNID value (Least Accurate / Least Stringent)
        WARNING:  Matching by VULNID can and will generate Type I and Type II Errors (False Positive / False Negative), specifically when upgrading checklists.

    .PARAMETER IgnoreNR
        Sets how this function will handle Not Reviewed checks in the Source Checklist File.
        Any check that was not reviewed is treated like a transparency (Ignored).
        This means that a NR Status and data will not be copied over to the destination checklist.
        Helpful when you are provided a partially completed checklist.
        
    .PARAMETER DataSet
        Default - All
        Infoms this function what set of data should be copied from SOURCE to DESTINATION
        Finding - Will copy only findings over, leaving the Asset Information alone in the destination.
        Asset - Will copy only asset information over, leaving the finding information alone in the destination
        All - Will copy both asset and finding information to destination    
    
    .EXAMPLE
        Import-Checklist -SourceCKL "C:\Temp\Source.ckl" -DestinationCKL "C:\Temp\Destination.ckl" -IgnoreNR

    #>
    param (
        [Parameter(Mandatory)]
        [string]$SourceCKL,
        [Parameter(Mandatory)]
        [string]$DestinationCKL,
        [PSDefaultValue(Help='RULEID')]
        [ValidateSet("RULEID","VULNID")]
        [string]$MatchOn = "RULEID",
        [switch]$IgnoreNR,
        [PSDefaultValue(Help='ALL')]
        [ValidateSet("ALL","ASSET","FINDING")]
        [string]$DataSet = "ALL"
    )
    
    [Checklist]$sCKL = [Checklist]::new($SourceCKL)
    [Checklist]$dCKL = [Checklist]::new($DestinationCKL)
    
    if(($DataSet -eq "ASSET") -or ($DataSet -eq "ALL")){
        $dCKL.ROLE = $sCKL.ROLE
        $dCKL.AssetType = $sCKL.AssetType
        $dCKL.HOST_NAME = $sCKL.HOST_NAME 
        $dCKL.HOST_IP = $sCKL.HOST_IP
        $dCKL.HOST_MAC = $sCKL.HOST_MAC
        $dCKL.HOST_FQDN = $sCKL.HOST_FQDN
        $dCKL.TARGET_COMMENT = $sCKL.TARGET_COMMENT
        $dCKL.TECH_AREA = $sCKL.TECH_AREA
        $dCKL.WEB_OR_DATABASE = $sCKL.WEB_OR_DATABASE
        $dCKL.WEB_DB_SITE = $sCKL.WEB_DB_SITE
        $dCKL.WEB_DB_INSTANCE = $sCKL.WEB_DB_INSTANCE
        $dckl.SetAssetInfo()
    }

    if(($DataSet -eq "FINDING") -or ($DataSet -eq "ALL")){
        $sCKL.AnalyzeVulns()
        $dCKL.AnalyzeVulns()
        foreach($sVuln in $sCKL.VULNS){
            if($dCKL.VULNS.VulnID -contains $sVuln.VulnID){
                $vulnIndex = $dCKL.VULNS.VulnID.IndexOf($sVuln.VulnID)
                if($dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.ATTRIBUTE_DATA[$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.VULN_ATTRIBUTE.IndexOf("Vuln_Num") -eq $sVuln.VulnID]){
                    #2x checking the index.
                    if(($MatchOn -eq "VULNID") -or ($dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.ATTRIBUTE_DATA[$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.VULN_ATTRIBUTE.IndexOf("Rule_ID") -eq $sVuln.RuleID])){
                        if($IgnoreNR.IsPresent -and $sVuln.Status -eq "Not_Reviewed"){
                            #SKIP!  
                        }
                        else{
                            $dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STATUS = $sVuln.STATUS
                            $dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].FINDING_DETAILS = $sVuln.FindingDetails
                            $dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].COMMENTS = $sVuln.Comments
                        }
                    }
                }

                Remove-Variable vulnIndex
            }
        }
    }

    $dCKL.xml.Save($DestinationCKL)
}

function Import-SCCXCCDF {
    <#
    .SYNOPSIS
        Imports SCC Tool XCCDF results into checklist.
        
    .DESCRIPTION
        
    
    .PARAMETER SourceXCCDF
        Path to the Source SCC XCCDF file (*_XCCDF-Results*.xml) that will be used within the import.

    .PARAMETER DestinationCKL
        Path to the destination Checklist file (.ckl) that will be used within the import.

    .PARAMETER MatchON
        Default - RuleID
        Sets how this function will perform matching/
        RuleID means findings will be matched by RULEID value (Most Accurate / Most Stringent)
        VulnID means findings will be matched by VULNID value (Least Accurate / Least Stringent)
        WARNING:  Matching by VULNID can and will generate Type I and Type II Errors (False Positive / False Negative), specifically when upgrading checklists.

    .PARAMETER FindingDetails
		Default - Basic
		Sets the amount of data to be placed in the Finding Details field.  Full will greatly increase the size of the checklist.
		Basic - [Tool]:  Result.  Example  SCC: Failed
		Full - Entire Benchmark.TestResult.RuleResult.Message.Text (Very Long)
        
    .PARAMETER DataSet
        Default - Finding
        Infoms this function what set of data should be copied from SOURCE to DESTINATION
        Finding - Will copy only findings over, leaving the Asset Information alone in the destination.
        Asset - Will copy only asset information over, leaving the finding information alone in the destination
        All - Will copy both asset and finding information to destination    
    
    .EXAMPLE
        Import-SCCXCCDF -SourceXCCDF "C:\Temp\Source.xml" -DestinationCKL "C:\Temp\Destination.ckl" -MatchOn VULNID -FindingDetails Full -DataSet ALL

    #>
    param (
        [Parameter(Mandatory)]
        [string]$SourceXCCDF,
        [Parameter(Mandatory)]
        [string]$DestinationCKL,
        [PSDefaultValue(Help='RULEID')]
        [ValidateSet("RULEID","VULNID")]
        [string]$MatchOn = "RULEID",
        [PSDefaultValue(Help='Basic')]
        [ValidateSet("Basic","Full")]     
		[string]$FindingDetails = "Basic",
        [PSDefaultValue(Help='FINDING')]
        [ValidateSet("ALL","ASSET","FINDING")]
        [string]$DataSet = "FINDING"
    )
    
    [SCCXCCDF]$sXCCDF = [SCCXCCDF]::new($SourceXCCDF)
    [Checklist]$dCKL = [Checklist]::new($DestinationCKL)
    
    if(($DataSet -eq "ASSET") -or ($DataSet -eq "ALL")){
        $dCKL.HOST_NAME = $sXCCDF.HOST_NAME 
        $dCKL.HOST_IP = $sXCCDF.HOST_IP
        $dCKL.HOST_MAC = $sXCCDF.HOST_MAC
        $dCKL.HOST_FQDN = $sXCCDF.HOST_FQDN
        $dCKL.SetHOSTNAME()
        $dCKL.SetIP()
        $dckl.SetMAC()
        $dCKL.SetFQDN()
        
    }

    if(($DataSet -eq "FINDING") -or ($DataSet -eq "ALL")){
        $sXCCDF.AnalyzeVulns()
        $dCKL.AnalyzeVulns()
        foreach($sVuln in $sXCCDF.VULNS){
            if($dCKL.VULNS.VulnID -contains $sVuln.VulnID){
                $vulnIndex = $dCKL.VULNS.VulnID.IndexOf($sVuln.VulnID)
                if($dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.ATTRIBUTE_DATA[$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.VULN_ATTRIBUTE.IndexOf("Vuln_Num") -eq $sVuln.VulnID]){
                    #2x checking the index.
                    if(($MatchOn -eq "VULNID") -or ($dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.ATTRIBUTE_DATA[$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STIG_DATA.VULN_ATTRIBUTE.IndexOf("Rule_ID") -eq $sVuln.RuleID])){
                        if(($sVuln.Status -eq "NotAFinding") -or ($sVuln.Status -eq "Open") -or ($sVuln.Status -eq "Not_Applicable") ){
                            $dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].STATUS = $sVuln.STATUS
							if($FindingDetails -eq "Basic"){
								$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].FINDING_DETAILS = "SCC Result: " + $sVuln.Status
							}
							elseif($FindingDetails -eq "Full"){
								$dCKL.xml.CHECKLIST.STIGS.iSTIG.VULN[$vulnIndex].FINDING_DETAILS = $sVuln.FindingDetails
							}
                            
                            
                        }
                    }
                }

                Remove-Variable vulnIndex
            }
        }
    }

    $dCKL.xml.Save($DestinationCKL)
}

function Get-STIG {
    <#
    .SYNOPSIS
        Downloads the selected STIG from public.cyber.mil and places the zip file in the provided location
        
    .DESCRIPTION
        Hunting and pecking cyber.mil for a specific STIG is a pain.  This function will download 1 or all STIGs based on your input.
    
    .PARAMETER STIGID
        Currently forces ALL STIGS.  This will be tricky as some STIG IDs are included in a collection, but their names have nothing to due with the file name.
        Need to work on this one.  Maybe a fuzzy match?
    
    .PARAMETER DestinationPath
        Location to place the downloaded STIG
    
    .EXAMPLE
        Get-STIG -Destination "C:\Temp\STIGs\" -STIGID "ALL"

    #>
    param (
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        [PSDefaultValue(Help='ALL')]
        [ValidateSet("ALL")]
        [string]$STIGID = "ALL"
    )
    if(Test-Path $DestinationPath){
        #Path is good,  Pull CyberMIL links to STIGs
        $CyberMIL = Invoke-WebRequest -Uri "https://public.cyber.mil/stigs/downloads/"
        If(($CyberMIL.Links | Where-Object {$_.href -like "*STIG.zip"}).count -gt 0){
            #STIGs are available to download.
            if($STIGID -eq "ALL"){
                #Download all STIGs
                ForEach($STIGLink in ($CyberMIL.Links | Where-Object {$_.href -like "*STIG.zip"}).href ){
                    $tempDestinationPath = $DestinationPath
                    if($tempDestinationPath[-1] -eq "\"){
                        $tempDestinationPath = $tempDestinationPath + ($STIGLink -replace ".*./","")
                    }
                    else{
                        $tempDestinationPath = $tempDestinationPath + "\" + ($STIGLink -replace ".*./","")
                    }
                    Invoke-WebRequest -Uri $STIGLink -OutFile $tempDestinationPath

                    Remove-Variable tempDestinationPath
                }
                ForEach($SRGLink in ($CyberMIL.Links | Where-Object {$_.href -like "*SRG.zip"}).href ){
                    $tempDestinationPath = $DestinationPath
                    if($tempDestinationPath[-1] -eq "\"){
                        $tempDestinationPath = $tempDestinationPath + ($SRGLink -replace ".*./","")
                    }
                    else{
                        $tempDestinationPath = $tempDestinationPath + "\" + ($SRGLink -replace ".*./","")
                    }
                    Invoke-WebRequest -Uri $SRGLink -OutFile $tempDestinationPath
                    Remove-Variable tempDestinationPath
                }
            }
            else{
                #Download just the selected STIG
            }
        }
        else {
            Write-Error -Message "Unable to access public.Cyber.Mil"
        }

    }
    else {
        Write-Error -Message "Provided path does not exist."
    }

    
}

function New-TemplateCKL {
<#
    .SYNOPSIS
        Creates a CKL File based on a provided STIG ZIP
        
    .DESCRIPTION
        
    
    .PARAMETER SourceZIP
        Path to the STIG ZIP
    
    .PARAMETER DestinationPath
        Path (Directory) to place the template CKL

    
    .EXAMPLE
        New-TemplateCKL -SourceZIP C:\Temp\SourceZIP.zip -DestinationPath C:\Temp

    #>
    param (
        [Parameter(Mandatory)]
        [string]$SourceZIP,
        [Parameter(Mandatory)]
        [string]$DestinationPath
    )
    #TO DO - Clean this up.. Most of the XML Writer code blocks can be put into a loop.  Did not do this initially because i wanted to make sure i was pulling the correct information from the XML.
    #Spot checked - The below code makes almost identical checklists as STIG Viewer, except for the STIG UUID and STIG viewer will place empty LEGACY id fields.
    
    #check paths
    
    #open STIG ZIP
    Add-Type -Assembly  "System.IO.Compression.Filesystem"
    $stigZIP = [Io.Compression.zipfile]::OpenRead($SourceZIP)
    $stigFiles = $stigZIP.Entries | Where-Object {$_.Name -like "*xccdf.xml"}
    ForEach($xccdf in $stigFiles){
        $xccdfStream = $xccdf.Open()
        $reader = New-Object IO.StreamReader($xccdfStream)
        $text = $reader.ReadToEnd()
        $XMLxccdf = (Select-Xml -Content $text -XPath /).node
        

        $lclSTIGID = $XMLxccdf.Benchmark.id
        $lclSTIGVersion = $XMLxccdf.Benchmark.version
        $lclSTIGRelease = $XMLxccdf.Benchmark.'plain-text'.'#text'[$XMLxccdf.Benchmark.'plain-text'.id.IndexOf("release-info")]
        $lclSTIGRelease = $lclSTIGRelease -replace " Benchmark.*",""
        $lclSTIGRelease = $lclSTIGRelease -replace "Release: ",""
        if($lclSTIGRelease -eq "R"){
            $lclSTIGRelease = $XMLxccdf.Benchmark.'plain-text'.'#text'
            $lclSTIGRelease = $lclSTIGRelease -replace " Benchmark.*",""
            $lclSTIGRelease = $lclSTIGRelease -replace "Release: ",""
        }
        $CKLFileName = $lclSTIGID + "_V" + $lclSTIGVersion + "R" + $lclSTIGRelease + ".ckl"
        $outFile = $DestinationPath + "\" + $CKLFileName
        $lclSTIGUUID = (New-Guid).Guid
        
        #Start XML Writer
        $SettingsXML = [System.Xml.XmlWriterSettings]::new()
        $SettingsXML.Indent = $true
        $SettingsXML.NewLineChars = "`r`n"
        $SettingsXML.IndentChars = "`t"

        $WriterXML = [System.Xml.XmlWriter]::Create($outFile,$SettingsXML)
        #$WriterXML = [System.Xml.XmlWriter]::new()
        $WriterXML.WriteComment("DISA STIG Viewer :: 2.17")
        $WriterXML.WriteStartElement("CHECKLIST")
        #region ASSET
            $WriterXML.WriteStartElement("ASSET")
                $WriterXML.WriteStartElement("ROLE") 
                    $WriterXML.WriteString("None")
                $WriterXML.WriteEndElement() #role
                $WriterXML.WriteStartElement("ASSET_TYPE") 
                    $WriterXML.WriteString("Computing")
                $WriterXML.WriteEndElement() #ASSET_TYPE
                $WriterXML.WriteStartElement("MARKING") 
                    $WriterXML.WriteString("CUI")
                $WriterXML.WriteEndElement() #MARKING
                $WriterXML.WriteStartElement("HOST_NAME") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #HOST_NAME
                $WriterXML.WriteStartElement("HOST_IP") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #HOST_IP
                $WriterXML.WriteStartElement("HOST_MAC") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #HOST_MAC
                $WriterXML.WriteStartElement("HOST_FQDN") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #HOST_FQDN
                $WriterXML.WriteStartElement("TARGET_COMMENT") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #TARGET_COMMENT
                #GET TECH AREA FROM LIST!!!!
                $WriterXML.WriteStartElement("TECH_AREA") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #TECH_AREA
                $WriterXML.WriteStartElement("TARGET_KEY") 
                    $WriterXML.WriteString($XMLxccdf.Benchmark.Group[0].Rule.reference.identifier)
                $WriterXML.WriteEndElement() #TARGET_KEY
                #GET WEB or DB FROM LIST!!!!
                $WriterXML.WriteStartElement("WEB_OR_DATABASE") 
                    $WriterXML.WriteString("false")
                $WriterXML.WriteEndElement() #WEB_OR_DATABASE
                $WriterXML.WriteStartElement("WEB_DB_SITE") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #WEB_DB_SITE
                $WriterXML.WriteStartElement("WEB_DB_INSTANCE") 
                    $WriterXML.WriteString("")
                $WriterXML.WriteEndElement() #WEB_DB_INSTANCE
            $WriterXML.WriteEndElement() #asset
        #endregion
            $WriterXML.WriteStartElement("STIGS")
                $WriterXML.WriteStartElement("iSTIG")
                    #region STIG INFO
                    $WriterXML.WriteStartElement("STIG_INFO")
                        #version    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("version")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($lclSTIGVersion)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #classification    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("classification")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString("UNCLASSIFIED")
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #customname    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("customname")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString("")
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #stigid    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("stigid")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($lclSTIGID)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #description    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("description")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($XMLXccdf.Benchmark.description)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #filename    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("filename")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($xccdf.Name)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #releaseinfo    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("releaseinfo")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($XMLxccdf.Benchmark.'plain-text'.'#text'[$XMLxccdf.Benchmark.'plain-text'.id.IndexOf("release-info")])
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #title    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("title")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($XMLXccdf.Benchmark.title)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #uuid    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("uuid")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($lclSTIGUUID)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #notice    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("notice")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString("terms-of-use")
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        #source    
                        $WriterXML.WriteStartElement("SI_DATA")
                        $WriterXML.WriteStartElement("SID_NAME")
                                $WriterXML.WriteString("source")
                            $WriterXML.WriteEndElement() #SID_NAME
                            $WriterXML.WriteStartElement("SID_DATA")
                                $WriterXML.WriteString($XMLXccdf.Benchmark.reference.source)
                            $WriterXML.WriteEndElement() #SID_DATA
                        $WriterXML.WriteEndElement() #SI_DATA
                        
                    $WriterXML.WriteEndElement() #STIG_INFO
                    #endregion
                    #region VULNS
                    ForEach($lclVULN in $XMLxccdf.Benchmark.Group){
                        $WriterXML.WriteStartElement("VULN")
                            #Vuln_Num
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Vuln_Num")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.id)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Severity
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Severity")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.rule.severity)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Group_Title
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Group_Title")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.title)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Rule_ID
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Rule_ID")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.rule.id)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Rule_Ver
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Rule_Ver")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.rule.version)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Rule_Title
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Rule_Title")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.rule.title)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Vuln_Discuss
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Vuln_Discuss")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(($lclVuln.Rule.description -replace ".*<VulnDiscussion>",""  -replace "</VulnDiscussion>.*",""))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #IA_Controls
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("IA_Controls")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<IAControls\>(.*)\<\/IAControls",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Check_Content
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Check_Content")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.Rule.check.'check-content')
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Fix_Text
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Fix_Text")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.Rule.fixtext.'#text')
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #False_Positives
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("False_Positives")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<FalsePositives\>(.*)\<\/FalsePositives",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #False_Negatives
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("False_Negatives")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<FalseNegatives\>(.*)\<\/FalseNegatives",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Documentable
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Documentable")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<Documentable\>(.*)\<\/Documentable",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Mitigations
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Mitigations")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<Mitigations\>(.*)\<\/Mitigations",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Potential_Impact
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Potential_Impact")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<PotentialImpacts\>(.*)\<\/PotentialImpacts",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Third_Party_Tools
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Third_Party_Tools")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<ThirdPartyTools\>(.*)\<\/ThirdPartyTools",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Mitigation_Control
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Mitigation_Control")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<MitigationControl\>(.*)\<\/MitigationControl",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Responsibility
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Responsibility")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<Responsibility\>(.*)\<\/Responsibility",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Security_Override_Guidance
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Security_Override_Guidance")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString(([regex]::Match($lclVuln.Rule.description.ToString(),"\<SeverityOverrideGuidance\>(.*)\<\/SeverityOverrideGuidance",[System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value))
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Check_Content_Ref
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Check_Content_Ref")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.Rule.check.'check-content-ref'.name)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Weight
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Weight")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclVuln.Rule.weight)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Class
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("Class")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString("Unclass")
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #STIGRef
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("STIGRef")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($XMLXccdf.Benchmark.title + " :: Version " + $lclSTIGVersion + ", " + $XMLxccdf.Benchmark.'plain-text'.'#text'[$XMLxccdf.Benchmark.'plain-text'.id.IndexOf("release-info")] )
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #TargetKey
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("TargetKey")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($XMLxccdf.Benchmark.Group[0].Rule.reference.identifier)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #STIG_UUID
                            $WriterXML.WriteStartElement("STIG_DATA")
                                $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                    $WriterXML.WriteString("STIG_UUID")
                                $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                    $WriterXML.WriteString($lclSTIGUUID)
                                $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                            $WriterXML.WriteEndElement() #STIG_DATA
                            #Legacy Loop!
                            ForEach($legacy in ($lclVULN.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"}).'#text'){
                                #LEGACY_ID
                                $WriterXML.WriteStartElement("STIG_DATA")
                                    $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                        $WriterXML.WriteString("LEGACY_ID")
                                    $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                    $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                        $WriterXML.WriteString($legacy)
                                    $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                                $WriterXML.WriteEndElement() #STIG_DATA
                            }

                            #CCI Loop
                            ForEach($CCI in ($lclVULN.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/CCI"}).'#text'){
                                #CCI_REF
                                $WriterXML.WriteStartElement("STIG_DATA")
                                    $WriterXML.WriteStartElement("VULN_ATTRIBUTE")
                                        $WriterXML.WriteString("CCI_REF")
                                    $WriterXML.WriteEndElement() #VULN_ATTRIBUTE
                                    $WriterXML.WriteStartElement("ATTRIBUTE_DATA")
                                        $WriterXML.WriteString($CCI)
                                    $WriterXML.WriteEndElement() #ATTRIBUTE_DATA
                                $WriterXML.WriteEndElement() #STIG_DATA
                            }

                            #status
                            $WriterXML.WriteStartElement("STATUS")
                                $WriterXML.WriteString("Not_Reviewed")
                            $WriterXML.WriteEndElement() #STATUS
                            #FINDING_DETAILS
                            $WriterXML.WriteStartElement("FINDING_DETAILS")
                                $WriterXML.WriteString("")
                            $WriterXML.WriteEndElement() #FINDING_DETAILS
                            #COMMENTS
                            $WriterXML.WriteStartElement("COMMENTS")
                                $WriterXML.WriteString("")
                            $WriterXML.WriteEndElement() #COMMENTS
                            #SEVERITY_OVERRIDE
                            $WriterXML.WriteStartElement("SEVERITY_OVERRIDE")
                                $WriterXML.WriteString("")
                            $WriterXML.WriteEndElement() #SEVERITY_OVERRIDE
                            #SEVERITY_JUSTIFICATION
                            $WriterXML.WriteStartElement("SEVERITY_JUSTIFICATION")
                                $WriterXML.WriteString("")
                            $WriterXML.WriteEndElement() #SEVERITY_JUSTIFICATION
                        $WriterXML.WriteEndElement() #VULN
                    }
                    #endregion
                $WriterXML.WriteEndElement() #iSTIG
            $WriterXML.WriteEndElement()#STIGS
        $WriterXML.WriteEndElement() #checklist
        #end write
        $WriterXML.flush()
        $WriterXML.close()


        $reader.Close()
        $xccdfstream.close()
    }
    $stigZIP.Dispose()



}


#endregion
