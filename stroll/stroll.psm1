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
#endregion
