<#
	Get-RedFishHwReport.ps1

  Add bmc details in the $bmcs var below and run in PowerShell as follows:
    .\Get-RedFishHwReport.ps1

  Should be hardware agnostic so long as the RedFish API is implemented.
  However please note RedFish URIs can change slightly between OEMs
  
  Tested with:
  - PowerShell v7
  - HPE Gen 10
  
#>

$bmcs = @"
name,ip,hardwareName,extraDisk
server1.domain.com,192.168.100.1,DL360-ru1,yes
server2.domain.com,192.168.100.2,DL360-ru5,yes
server3.domain.com,192.168.100.3,DL360-ru6,yes
"@ | ConvertFrom-Csv


$bmccreds = Get-Credential -Message "Please enter bmc username and password"

# Script init variables - do not change
$runDate = Get-Date -UFormat '%Y%m%d-%H%M%S'
$scriptLogPath = "$env:TEMP\bmc-report_script-log_$($runDate).log"
$configReport = "$env:TEMP\bmc-report_report_$($runDate).html"

# Start - Equivalent to "curl -k". Allows connection to URIs with invalid SSL certs.
$code= @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
Add-Type -TypeDefinition $code -Language CSharp
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
# End - Equivalent to "curl -k". Allows connection to URIs with invalid SSL certs.


# Start - convert creds to use basic auth with redfish
$pair = "$($bmccreds.GetNetworkCredential().UserName):$($bmccreds.GetNetworkCredential().Password)"
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
}
# End - convert creds to use basic auth with redfish

# Start - Define common functions
function Write-StopError {
    param (
        $message
    )
    $msgContent = "$(Get-Date -UFormat '%Y-%m-%d-%H:%M:%S') - $message"
    $msgContent | Out-File -Append -FilePath $scriptLogPath
    Write-Error $msgContent -ErrorAction Stop
}

function Write-DatedMessage {
    param (
        $message
    )
    $msgContent = "$(Get-Date -UFormat '%Y-%m-%d-%H:%M:%S') - $message"
    $msgContent | Out-File -Append -FilePath $scriptLogPath
    Write-Host $msgContent
}
# End - Define common functions

$allNodes = @()
$missingNodes = @()
# Start - Per node checks
foreach ($bmc in $bmcs) {
    
    $thisNode = $bmc.name
    $thisIP = $bmc.ip
    $thisHWName = $bmc.hardwareName
    $thisExtraDisk = $bmc.extraDisk

    Write-DatedMessage -message "Checking $thisNode - $thisIP"

    # For more info regard ?`$expand=. used below, see https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/odataqueryoptions/#ilo-expand
    $test = Invoke-WebRequest -Uri https://$($thisIP)/redfish/v1/systems/1?`$expand=. -Headers $Headers -UseBasicParsing -TimeoutSec 5

    if ( !$? ){
        $missingObject = @{} | Select Name,IP,HardwareName
        $missingObject.Name = $thisNode
        $missingObject.IP = $thisIP
        $missingObject.HardwareName = $thisHWName
        $missingNodes += $missingObject
    } else {
        $reportObject = @{} | Select Node,ShouldHaveExtraDisk,Serial,BiosVersion,Cpu,MemoryGB,Disks,RaidVolumeCount,RaidVolumes,MacAddresses,BiosConfig,Firmware
        $thisSystem = $test.Content | ConvertFrom-Json
        $thisBootMode = $thisSystem.Boot.BootSourceOverrideMode
        $thisBiosVersion = $thisSystem.BiosVersion
        $thisMemGB = $thisSystem.MemorySummary.TotalSystemMemoryGiB
        $thisCpu = "$($thisSystem.ProcessorSummary.Count) x $($thisSystem.ProcessorSummary.Model)"
        $thisSerial = $thisSystem.SerialNumber
        # In case we want to check any particular BIOS options
        $thisBios = $thisSystem.Bios.Attributes | Select BootMode,ConsistentDevNaming,IntelProcVtd,Numa,NvmeRaid,ProcHyperthreading,ProcTurbo,ProcVirtualization,Sriov,SubNumaClustering,TimeZone,WorkloadProfile

        $thisEthernetInterfaces = (Invoke-WebRequest -Uri https://$($thisIP)/redfish/v1/Systems/1/EthernetInterfaces?`$expand=. -Headers $Headers -UseBasicParsing).Content | ConvertFrom-Json
        $thisMacAddresses = $thisEthernetInterfaces.Members | Select Id,MACAddress

        $thisFirmware = (Invoke-WebRequest -Uri https://$($thisIP)/redfish/v1/UpdateService/FirmwareInventory?`$expand=. -Headers $Headers -UseBasicParsing).Content | ConvertFrom-Json
        $thisFirmwareInv = $thisFirmware.Members | Select Name,Version

        $thisStorage = (Invoke-WebRequest -Uri https://$($thisIP)/redfish/v1/Systems/1/Storage?`$expand=. -Headers $Headers -UseBasicParsing).Content | ConvertFrom-Json
        $thisStorageNested = $thisStorage.Members."@odata.id" | %{(Invoke-WebRequest -Uri https://$($thisIP)$($_)?`$expand=. -Headers $Headers -UseBasicParsing).Content | ConvertFrom-Json}
        # Physical disks
        $thisDrives =  $thisStorageNested.Drives | Select Name
        # RAID volumes
        $thisVolumeCount = $thisStorageNested.Volumes."Members@odata.count"
        $thisVolumes = $thisStorageNested.Volumes.Members

        $reportObject.Node = "Name: $thisNode`nIP: $thisIP`nHardwareName: $thisHWName"
        $reportObject.ShouldHaveExtraDisk = $thisExtraDisk
        $reportObject.Serial = $thisSerial
        $reportObject.BiosVersion = $thisBiosVersion 
        $reportObject.Cpu = $thisCpu 
        $reportObject.MemoryGB = $thisMemGB
        $reportObject.Disks = $thisDrives
        $reportObject.RaidVolumeCount = $thisVolumeCount 
        $reportObject.RaidVolumes = $thisVolumes
        $reportObject.MacAddresses = $thisMacAddresses
        $reportObject.BiosConfig = $thisBios
        $reportObject.Firmware = $thisFirmwareInv

        $allNodes += $reportObject
    }

}

# HTML conversion
$stripped = @();
foreach ($node in $allNodes){
    $strippedNode = $node.psobject.Copy()
    $strippedNode.Node = "$($node.Serial) Node PLACEHOLDER"
    $strippedNode.Disks = "$($node.Serial) Disks PLACEHOLDER"
    $strippedNode.MacAddresses = "$($node.Serial) MacAddresses PLACEHOLDER"
    $strippedNode.BiosConfig = "$($node.Serial) BiosConfig PLACEHOLDER"
    $strippedNode.Firmware = "$($node.Serial) Firmware PLACEHOLDER"
    $strippedNode.RaidVolumes = "$($node.Serial) RaidVolumes PLACEHOLDER"

    $stripped += $strippedNode
}


$cssHeader = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

$biosTable = $stripped | Select Node,BiosConfig  | ConvertTo-Html -PreContent "<h1>Node Bios Summary:</h1>" -Fragment
foreach ($node in $allNodes){
    # add Bios Summary as separate
    $nodeHtml = $node.Node.Replace("`n","<br>")
    $biosHtml = $node.BiosConfig | ConvertTo-Html -Fragment -As List | Out-String #($node.BiosConfig | Out-String).Trim().Replace("`r`n","<br>") #

    # Add to additionalHtml
    $biosTable = $biosTable.Replace("$($node.Serial) Node PLACEHOLDER",$nodeHtml)
    $biosTable = $biosTable.Replace("$($node.Serial) BiosConfig PLACEHOLDER",$biosHtml)   
    
}
$biosTable = $biosTable | Out-String

$firmwareTable = $stripped | Select Node,Firmware  | ConvertTo-Html -PreContent "<h1>Node Firmware Summary:</h1>" -Fragment
foreach ($node in $allNodes){
    # add Bios Summary as separate
    $nodeHtml = $node.Node.Replace("`n","<br>")
    $firmwareHtml = $node.Firmware | ConvertTo-Html -Fragment | Out-String #($node.Firmware | Out-String).Trim().Replace("`r","<br>") #

    # Add to additionalHtml
    $firmwareTable = $firmwareTable.Replace("$($node.Serial) Node PLACEHOLDER",$nodeHtml)
    $firmwareTable = $firmwareTable.Replace("$($node.Serial) Firmware PLACEHOLDER",$firmwareHtml) 
    
}
$firmwareTable = $firmwareTable | Out-String

$missingNodesTable = $missingNodes | ConvertTo-Html -Fragment -PreContent "<h1>Unreachable Nodes</h1>" | Out-String

$baseHTML = $stripped | Select Node,ShouldHaveExtraDisk,Serial,BiosVersion,Cpu,MemoryGB,Disks,RaidVolumeCount,RaidVolumes,MacAddresses
$baseHTML = $baseHTML | ConvertTo-Html -Head $cssHeader -PreContent "<p>Report generated at: $(Get-Date -UFormat '%Y-%m-%d %H:%M:%S')</p><h1>Node Overview Summary:</h1>" -PostContent $missingNodesTable,$biosTable,$firmwareTable

foreach ($node in $allNodes){
    # Create individual HTML tables / formatting
    $nodeHtml = $node.Node.Replace("`n","<br>")
    $diskHtml = $node.Disks | ConvertTo-Html -Fragment -Property Name | Out-String  
    $macHtml = $node.MacAddresses | ConvertTo-Html -Fragment | Out-String #($node.MacAddresses | Out-String).Trim().Replace("`r`n","<br>") #

    # Add to the base html
    $baseHTML = $baseHTML.Replace("$($node.Serial) Node PLACEHOLDER",$nodeHtml)
    $baseHTML = $baseHTML.Replace("$($node.Serial) Disks PLACEHOLDER",$diskHtml)
    $baseHTML = $baseHTML.Replace("$($node.Serial) MacAddresses PLACEHOLDER",$macHtml)

    # Format and add RAID info only if it exists
    if ($node.RaidVolumeCount -gt 0) {
        $raidHtml = $node.RaidVolumes | ConvertTo-Html -Fragment | Out-String
    } else {
        $raidHtml = ""
    }
    $baseHTML = $baseHTML.Replace("$($node.Serial) RaidVolumes PLACEHOLDER",$raidHtml)
}

$baseHTML | Out-File $configReport

start $configReport

Write-DatedMessage "Report completed. It should open automatically however if not, please find it here: $configReport"
