#Requires -Version 7.0

<#
.SYNOPSIS
    Powershell script to export NSX DFW rules into csv file.
.DESCRIPTION
    Powershell script to export NSX DFW rules into csv file. 
    Each rule is exported including realized source/destination IPs/VMs and service protocol/port number.
.PARAMETER NsxManager
    String
    URL of your NSX manager instance eg. 'https://nsxmanager.your.domain.local'.
.PARAMETER Authentication
    String
    Authentication method to be used for NSX rest api calls.
    Possible values: "basic", "certificate"
.PARAMETER Certificate
    X509Certificate
    Required when authentication is set to "certificate".
.PARAMETER Credentials
    PSCredential
    Required when authentication is set to "basic".
.PARAMETER outPath
    String
    Specifies the name and path for the CSV-based output file.
.NOTES
    Depending on NSX environment size, the script can generate many API calls. Performance of a Nsx Manager can be impacted.
    NSX manager's SSL cetificate validation is turned off.
.EXAMPLE
    PS> .\Export-NsxDfwRules.ps1 -NsxManager 'https://nsxmanager.your.domain.local' -authentication 'certificate' -certificate (Get-PfxCertificate -FilePath 'yourCert.pfx') -outPath 'output.csv'
    PS> .\Export-NsxDfwRules.ps1 -NsxManager 'https://nsxmanager.your.domain.local' -authentication 'basic' -credentials (get-credential) -outPath 'output.csv'
.OUTPUTS
    CSV file with rules in the folowing structure:
    "policy";"id";"rule_name";"action";"source_groups";"source_vms";"source_ips";"destination_groups";"destination_vms";"destination_ips";"services";"profiles";"disabled";"_last_modified_time";"_last_modified_user";"parent_path"
#>

##########################
# Global Parameters
##########################
param (
        [Parameter(Mandatory=$true)]
        [string]$nsxManager,

        [Parameter(Mandatory=$true, 
        HelpMessage="Authentication method for Nsx rest api calls")]
        [ValidateSet("basic", "certificate")]
        [string]$Authentication,

        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credentials,

        [Parameter(Mandatory=$true)]
        [string]$outPath

    )

##########################
# Functions
##########################

# Universal function to invoke NSX Rest API call. Returns API response.
function Invoke-NsxApiCall{
    param(
        [Parameter(Mandatory=$true,
        HelpMessage="Api endpoint to call eg. '/policy/api/v1/infra/domains/default/security-policies' to return dfw policies. ")]
        [string]$endpoint
    )

    $uri = $nsxManager + $endpoint
    try {
        if($authentication -eq 'certificate'){
            $response = Invoke-RestMethod -uri $uri -method get -SkipCertificateCheck -Certificate $certificate
        }elseif($authentication -eq 'basic'){
            $response = Invoke-RestMethod -uri $uri -method get -SkipCertificateCheck -Authentication Basic -Credential $credentials
        }else{
            write-error "You need to specify authentication method in -Authentication global param."
            $response = $Null
        }
    }catch {
        write-error "Failed to invoke Nsx api call with uri $($uri). Error $($_.Exception.Message)"
        $response = $null
    }

    return $response
}

# Returns NSX Distributed FW policies
function Get-NsxDfwPolicies(){
    $endpoint= '/policy/api/v1/infra/domains/default/security-policies' 
    $r = Invoke-NsxApiCall -endpoint $endpoint
    return $r.results
}

# Returns NSX DFW rules for given poilcy
function Get-NsxDfwPolicyRules{
    param(
        [string]$policyId,
        [string]$policyPath
    )
    if($policyId){
        $endpoint = '/policy/api/v1/infra/domains/default/security-policies/' + $policyId
    }elseif($policyPath){
        $endpoint = '/policy/api/v1' + $policyPath
    }else{
        Write-Error "You need to specify either policyId or policyPath."
        return $null
    }
    $r = Invoke-NsxApiCall -endpoint $endpoint
    return $r.rules
}

# Returns realized NSX Inventory Group Member (IP address or virtual machines)
function Get-NsxInventoryGroupMember{
    param(
       # [string]$groupId,
        [parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$groupPath,

        [parameter(Mandatory=$true,
        HelpMessage="Specify either 'IP' or 'VM' whether to return ip-addresses or virual-machines group members.")]
        [ValidateSet('IP', 'VM')]
        [string]$memberType
    )

    [system.collections.ArrayList]$members = @()

    $groupPath | foreach-object{

        if($_ -eq 'ANY'){  
            $members.add('ANY') | out-null 
        }elseif($_ -match '^\d+\.\d+\.\d+\.\d+(\/\d+)?'){
            $members.add($_) | out-null 
        }else{    

            if ($memberType -eq 'IP'){
                $endpoint = "/policy/api/v1$($_)/members/ip-addresses"
                $r = Invoke-NsxApiCall -endpoint $endpoint
                $members.add($r.results) | out-null

            }elseif($memberType -eq 'VM'){
                $endpoint = "/policy/api/v1$($_)/members/virtual-machines"
                $r = Invoke-NsxApiCall -endpoint $endpoint
                $members.add($r.results.display_name) | out-null
            }
        }
    }
    return $members
}

#Returns NSX Inventory Service Entries. NestedServiceServiceEntries are searched recursively.
function Get-NsxInventoryServiceEntries{
    param(
        [string]$servicePath,
        [string]$serviceId
    )
    #Validate function params
    if($serviceId) {
        $endpoint = "/policy/api/v1/infra/services/$($serviceId)"
    }elseif($servicePath){
        $endpoint = "/policy/api/v1$($servicePath)"
    }else{
        Write-Error "You need to specify either serviceId or servicePath."
        return $null
    }

    $serviceEntries = Invoke-NsxApiCall -endpoint $endpoint
    [system.collections.ArrayList]$serviceEntriesOutput = @()

    foreach($entry in $serviceEntries.service_entries){
        switch ($entry.resource_type) {
            'L4PortSetServiceEntry'{ 
                $obj = [pscustomobject]@{"resource_Type"= $entry.resource_type
                                        "service_entry"= $entry.id
                                        "protocol" = $entry.l4_protocol
                                        "ports" = $entry.destination_ports
                                        "service" = "$($entry.l4_protocol)_$($entry.destination_ports)"
                                    }
                $serviceEntriesOutput.add($obj) | out-null 
            }
            'NestedServiceServiceEntry'{ 
                Get-NsxInventoryServiceEntries -serviceId $entry.id
            }
            'ALGTypeServiceEntry'{
                $obj = [pscustomobject]@{"resource_Type"= $entry.resource_type
                                        "service_entry"= $entry.id
                                        "protocol" = $entry.alg
                                        "ports" = $entry.destination_ports
                                        "service" = "$($entry.l4_protocol)_$($entry.destination_ports)"
                                        }
                $serviceEntriesOutput.add($obj) | out-null
            }
            'ICMPTypeServiceEntry'{
                $obj = [pscustomobject]@{"resource_Type"= $entry.resource_type
                                        "service_entry"= $entry.id
                                        "protocol" = $entry.protocol
                                        "port" = $entry.icmp_type
                                        "service" = "$($entry.protocol)_$($entry.icmp_type)"
                                        } #;"icmp_code" = $entry.icmp_code
                $serviceEntriesOutput.add($obj) | out-null
             }
            'IGMPTypeServiceEntry'{
                $obj = [pscustomobject]@{"resource_Type"= $entry.resource_type 
                                        "service_entry"= $entry.id
                                        "protocol" = "IGMP"
                                        "port" = $entry.display_name
                                        "service" = "IGMP_$($entry.display_name)"
                                        }
                $serviceEntriesOutput.add($obj) | out-null
             }
            'IPProtocolServiceEntry'{
                $obj = [pscustomobject]@{"resource_Type"= $entry.resource_type
                                            "service_entry"= $entry.id
                                            "protocol" = "IP"
                                            "port" = $entry.protocol_number
                                            "service" = "IP_$($entry.protocol_number)"
                                        }
                    $serviceEntriesOutput.add($obj) | out-null
                }
            'EtherTypeServiceEntry'{
                $obj = [pscustomobject]@{"resource_Type"=$entry.resource_type
                                            "service_entry"= $entry.id
                                            "protocol" = "Ether"
                                            "port" = $entry.display_name
                                            "service" = "Ether_$($entry.display_name)"
                                        }
                $serviceEntriesOutput.add($obj) | out-null 
            }
            Default {}
        }
    }
    return $serviceEntriesOutput
}

#Helper function to loop through service entries if multiple services are set in a rule. 
#Filters 'ANY' service entry as it doesn't exists in inventory and Api call fails.
function Join-ServiceEntries{
    param(
        [parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$servicePath
    )

    [System.Collections.ArrayList]$serviceEntries = @()
    foreach($service in $servicePath){
        if($service -ne 'ANY'){
            $entries = Get-NsxInventoryServiceEntries -servicePath $service
            $serviceEntries.add($entries) | Out-Null
        }else{
            $entry = [pscustomobject]@{
                "resource_Type"= 'ANY'
                "service_entry"= 'ANY'
                "protocol" = 'ANY'
                "port" = 'ANY'
                "service" = 'ANY'
                }
            $serviceEntries.add($entry) | Out-Null
        }
    }
    
    return $serviceEntries
}

##########################
# Main Script logic
##########################
# Get NSX DFW policies
$policies = Get-NsxDfwPolicies

# Exit the script if no policy found or api call failed.
if(!$policies){
    write-host "Either no NSX DFW policy found or API call failed. Exiting..."
    Exit
}

write-host "Nsx DFW policies count: $($policies.count)"
# ArrayList to add rules to
[system.Collections.ArrayList]$rulesOutput = @()

#Loop through each rule in each policy and add rule to ArrayList.
#for ($i = 0; $i -lt 4; $i++) {
for ($i = 0; $i -lt $policies.Count; $i++) {

    $percentage = [math]::Round(($i / $policies.Count)*100)
    Write-Progress -Activity 'Processing DFW policies' -Status "$percentage% Complete: $($policies[$i].display_name)" -PercentComplete $percentage 

        $rules = Get-NsxDfwPolicyRules -policyId $policies[$i].id
        foreach($rule in $rules) {
            $obj = [PSCustomObject]@{
                "policy" = $policies[$i].display_name
                "id" = $rule.rule_id
                "rule_name" = $rule.display_name
                "action" = $rule.action
                "source_groups" = $rule.source_groups
                "source_ips" = Get-NsxInventoryGroupMember -grouppath $rule.source_groups -memberType 'ip'
                "source_vms" = Get-NsxInventoryGroupMember -grouppath $rule.source_groups -memberType 'vm'
                "destination_groups" = $rule.destination_groups
                "destination_vms" = Get-NsxInventoryGroupMember -grouppath $rule.destination_groups -memberType 'vm'
                "destination_ips" = Get-NsxInventoryGroupMember -grouppath $rule.destination_groups -memberType 'ip'
                "services" = join-ServiceEntries -servicePath $rule.services
                "profiles" = $rule.profiles
                "disabled" = $rule.disabled
                "_last_modified_user" =  $rule._last_modified_user
                "_last_modified_time" = $rule._last_modified_time
                "parent_path" = $rule.parent_path 
            }
            $rulesOutput.Add($obj) | out-null
        }
}

write-host "Processing rules..."

#Parse rulesOutput to desired csv format
$rulesOutput | Select-Object policy, id, action, rule_name,`
                @{name='source_groups'; expression={([string[]]$_.source_groups) -join ', '}},`
                @{name='source_vms'; expression={([string[]]$_.source_vms) -join ', '}},`
                @{name='source_ips'; expression={([string[]]$_.source_ips) -join ', '}},`
                @{name='destination_groups'; expression={([string[]]$_.destination_groups) -join ', '}},`
                @{name='destination_vms'; expression={([string[]]$_.destination_vms) -join ', '}},`
                @{name='destination_ips'; expression={([string[]]$_.destination_ips) -join ', '}},`
                @{name='services'; expression={($_.services | Select-Object -ExpandProperty service) -join ', '}},`
                @{name='profiles'; expression={([string[]]$_.profiles) -join ', '}},`
                disabled, _last_modified_time, _last_modified_user, parent_path |
                export-csv -path $outPath -delimiter ';' -force -Encoding unicode -NoTypeInformation

write-host "Done! Proccessed $($rulesOutput.count) rules."
write-host "Exported rules saved to file: $($outPath)."
