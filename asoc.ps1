# Copyright 2023, 2024 HCL America
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$Os = 'linux'
if($IsMacOS){
  $Os = 'mac'
}elseif($IsWindows){
  $Os = 'win'
}

$ClientType = "github-dast-$Os-$env:GITHUB_ACTION_REF"

Write-Host "Loading Library functions from asoc.ps1"

# =====================================================
# PowerShell 7 SAFE SSL BYPASS WRAPPERS
# =====================================================

function Invoke-ASoCRestMethod {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Params,
        $Body = $null
    )

    if ($null -ne $Body) {
        return Invoke-RestMethod @Params -Body $Body -SkipCertificateCheck
    } else {
        return Invoke-RestMethod @Params -SkipCertificateCheck
    }
}

function Invoke-ASoCWebRequest {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Params,
        $OutFile = $null
    )

    if ($null -ne $OutFile) {
        return Invoke-WebRequest @Params -OutFile $OutFile -SkipCertificateCheck
    } else {
        return Invoke-WebRequest @Params -SkipCertificateCheck
    }
}

# =====================================================
# FUNCTIONS (ALL UPDATED TO USE WRAPPERS)
# =====================================================

function Login-ASoC {

  $jsonBody = @{
    KeyId     = $env:INPUT_ASOC_KEY
    KeySecret = $env:INPUT_ASOC_SECRET
  }

  $params = @{
      Uri    = "$global:BaseAPIUrl/Account/ApiKeyLogin"
      Method = 'POST'
      Body   = $jsonBody | ConvertTo-Json
      Headers = @{
          'Content-Type' = 'application/json'
          'accept'       = 'application/json'
          'ClientType'   = "$ClientType"
      }
  }

  $Members = Invoke-ASoCRestMethod -Params $params
  $global:BearerToken = $Members.token

  if($global:BearerToken){
    Write-Host "Login successful"
  } else {
    Write-Error "Login failed... exiting"
    exit 1
  }
}

function Lookup-ASoC-Application ($ApplicationName) {

  $params = @{
      Uri    = "$env:INPUT_BASEURL/Apps"
      Method = 'GET'
      Headers = @{
          'Content-Type' = 'application/json'
          Authorization  = "Bearer $global:BearerToken"
      }
  }

  $Members = Invoke-ASoCRestMethod -Params $params
  return $Members.Items.Contains($ApplicationName)
}

function Run-ASoC-FileUpload($filepath){

  $params = @{
    Uri    = "$global:BaseAPIUrl/FileUpload"
    Method = 'Post'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
    }
    Form = @{
      'uploadedFile' = Get-Item -Path $filepath
    }
  }

  $upload = Invoke-ASoCRestMethod -Params $params
  Write-Host "File Uploaded - File ID: $($upload.FileId)"
  return $upload.FileId
}

function Run-ASoC-DynamicAnalyzerAPI($json){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Scans/Dast"
    Method = 'POST'
    Body   = $json
    Headers = @{
        'Content-Type' = 'application/json'
        'ClientType'   = "$ClientType"
        Authorization  = "Bearer $global:BearerToken"
    }
  }

  $Members = Invoke-ASoCRestMethod -Params $params
  return $Members.Id
}

function Run-ASoC-ScanCompletionChecker($scanID){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Scans/$scanID/Executions"
    Method = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
    }
  }

  Write-Host "Waiting for Scan Completion..." -NoNewLine
  $counter = 0

  while(($scan_status -ne "Ready") -and ($counter -lt $env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES*60)){

    $output = Invoke-ASoCRestMethod -Params $params
    $scan_status = $output.Status
    Start-Sleep -Seconds 15
    $counter += 15
    Write-Host "." -NoNewline

    if($scan_status -eq 'Failed'){
      Write-Error "Scan failed: $($output.UserMessage)"
      exit 1
    }
  }

  Write-Host ""
}

function Run-ASoC-GenerateReport ($scanID) {

  $params = @{
    Uri    = "$global:BaseAPIUrl/Reports/Security/Scan/$scanID"
    Method = 'POST'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }

  $body = @{
    Configuration = @{
      Summary = $true
      Details = $true
      ReportFileType = "HTML"
      Title = "$global:scan_name"
      Locale = "en-US"
    }
  }

  $output = Invoke-ASoCRestMethod -Params $params -Body ($body | ConvertTo-Json)
  return $output.Id
}

function Run-ASoC-DownloadReport($reportID){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Reports/$reportID/Download"
    Method = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Accept'      = 'text/html'
    }
  }

  $output = Invoke-ASoCRestMethod -Params $params
  Out-File -InputObject $output -FilePath ".\AppScan_Security_Report-$env:GITHUB_SHA.html"
}

function Run-ASoC-GetIssueCount($scanID){

  $params = @{
      Uri    = "$global:BaseAPIUrl/Issues/Scan/$scanID?applyPolicies=None"
      Method = 'GET'
      Headers = @{
        Authorization = "Bearer $global:BearerToken"
      }
  }

  $jsonOutput = Invoke-ASoCRestMethod -Params $params
  return $jsonOutput.Items
}

function Run-ASoC-CancelScanExecution($executionId){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Scans/Execution/$executionId/"
    Method = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
    }
  }

  return Invoke-ASoCWebRequest -Params $params
}

function Run-ASoC-CreatePresence($presenceName){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Presences"
    Method = 'POST'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }

  $jsonBody = @{ PresenceName = $presenceName }

  $jsonOutput = Invoke-ASoCRestMethod -Params $params -Body ($jsonBody | ConvertTo-Json)
  return $jsonOutput.Id
}

function Run-ASoC-DownloadPresence($presenceId, $OutputFileName, $platform){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Presences/$presenceId/Download/$platform"
    Method = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
    }
  }

  return Invoke-ASoCWebRequest -Params $params -OutFile $OutputFileName
}

function Run-ASoC-DeletePresence($presenceId){

  $params = @{
    Uri    = "$global:BaseAPIUrl/Presences/$presenceId"
    Method = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
    }
  }

  try {
    Invoke-ASoCWebRequest -Params $params
    Write-Host "Successfully deleted presence $presenceId"
  } catch {
    Write-Host "Failed to delete presence $presenceId"
  }
}