param(
  [string]$PveHost = "10.0.0.5",     # IP/host van je Proxmox NUC
  [string]$PveNode = "pve1",           # Node-naam zoals zichtbaar in de GUI (bijv. "pve" of "pve1")
  [string]$Storage = "local",         # Storage ID voor ISO en disk (bijv. "local" of "local-lvm")
  [string]$IsoPath = "C:\isos\RHEL\rhel-9.6-x86_64-dvd.iso",  # Pad naar je RHEL ISO op Windows
  # Indien je al een ISO op de Proxmox storage hebt gezet, geef hier de bestandsnaam (bv 'rhel-9.6-x86_64-dvd.iso')
  [string]$IsoFilename = "",
  [int]$Vmid = 210,                   # Uniek VM ID
  [string]$VmName = "rhel-test",      # VM-naam
  [int]$Cores = 2,
  [int]$RamMb = 4096,
  [int]$DiskGb = 40,
  [string]$Bridge = "vmbr10"
  ,
  # Voor testdoeleinden: inline token/secret (plain-text). Vervang of verwijder na tests.
  [string]$ApiTokenId = "root@pam!automation",
  [string]$ApiSecret = "2904cebc-9b4a-4ffb-a455-b11315cb11d7",
  # Indien je tijdelijk self-signed certs gebruikt: zet -Insecure om cert-validatie over te slaan
  [switch]$Insecure
  ,
  # Als je alleen de ISO wilt uploaden en geen VM wilt aanmaken/starten
  [switch]$UploadOnly
)

if (-not $ApiTokenId -or -not $ApiSecret) {
  Write-Host "LET OP: geen API token/secret gevonden in parameters of omgeving. Gebruik plain-text defaults alleen voor testing." -ForegroundColor Yellow
} else {
  Write-Host "API token/secret geladen (plain-text testing mode). Vergeet niet te revoke na test." -ForegroundColor Yellow
}

# ---- HTTP client ----
$loadedHttp = $false
try {
  Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
  $loadedHttp = $true
} catch {
  Write-Host "Waarschuwing: System.Net.Http assembly kon niet geladen worden. Val terug op alternatieve methodes." -ForegroundColor Yellow
}

if ($Insecure) {
  Write-Host "Insecure mode: skipping server certificate validation (ServicePointManager)" -ForegroundColor Yellow
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) return $true }
}

# Force modern TLS versions (helps on older PowerShell/.NET setups)
try {
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  Write-Host "Using SecurityProtocol: TLS1.2" -ForegroundColor Gray
} catch {
  Write-Host "Kon SecurityProtocol niet instellen: $($_.Exception.Message)" -ForegroundColor Yellow
}

if ($loadedHttp) {
  $handler = New-Object System.Net.Http.HttpClientHandler
  # force TLS1.2 on handler if the property exists (newer runtimes)
  try {
    if ($handler.GetType().GetProperty('SslProtocols')) {
      $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
      Write-Host "HttpClientHandler configured for SslProtocols::Tls12" -ForegroundColor Gray
    }
  } catch {
    Write-Host "Kon SslProtocols niet instellen op HttpClientHandler: $($_.Exception.Message)" -ForegroundColor Yellow
  }
  $client = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(30)
} else {
  throw "HttpClient types niet beschikbaar. Zorg dat System.Net.Http beschikbaar is of run dit script in PowerShell Core (pwsh)."
}

$AuthHeader = "PVEAPIToken=$ApiTokenId=$ApiSecret"
$client.DefaultRequestHeaders.Remove("Authorization") | Out-Null
$client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $AuthHeader) | Out-Null
$BaseUrl = "https://$($PveHost):8006/api2/json"
# fallback: use curl.exe if HttpClient/Invoke-RestMethod cannot talk to the host :))))
$UseCurl = $false

function Invoke-FormPost {
  param(
    [string]$Uri,
    [hashtable]$Body
  )
  if ($UseCurl) {
    # Build application/x-www-form-urlencoded body string (heeel vervelend)
    $pairs = @()
    foreach ($k in $Body.Keys) {
      $v = [string]$Body[$k]
      $pairs += "{0}={1}" -f $k, [System.Uri]::EscapeDataString($v)
    }
    $bodyStr = $pairs -join '&'
    $curlArgs = @('-k','-sS','-H',"Authorization: $AuthHeader", '--data', $bodyStr, $Uri)
    $out = & curl.exe @curlArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw "curl POST to $Uri failed: $out"
    }
    return $out
  } else {
    # Convert Hashtable to IEnumerable<KeyValuePair<string,string>> for FormUrlEncodedContent
  $kvType = [System.Type]::GetType('System.Collections.Generic.KeyValuePair`2[[System.String, mscorlib],[System.String, mscorlib]]')
  $listType = ([System.Type]::GetType('System.Collections.Generic.List`1, mscorlib')).MakeGenericType($kvType)
  $pairs = [System.Activator]::CreateInstance($listType)
    foreach ($k in $Body.Keys) {
  $pair = [System.Activator]::CreateInstance($kvType, $k, [string]$Body[$k])
  $pairs.GetType().GetMethod('Add').Invoke($pairs, @($pair)) | Out-Null
    }
    $content = New-Object System.Net.Http.FormUrlEncodedContent($pairs)
    $resp = $client.PostAsync($Uri, $content).Result
    $txt = $resp.Content.ReadAsStringAsync().Result
    if (-not $resp.IsSuccessStatusCode) {
      throw "POST $Uri failed: $($resp.StatusCode) - $txt"
    }
    return $txt
  }
}

# 0) Snel testje: bereikbaarheid & auth
Write-Host "Check API toegang op $PveHost..."
try {
  Write-Host "DEBUG: BaseUrl='$BaseUrl'`nDEBUG: PveHost='$PveHost'"
  try {
    $uriVersion = [uri]("$($BaseUrl)/version")
  } catch {
    throw "Kan versie-URI niet bouwen: $($_.Exception.Message) - BaseUrl='$BaseUrl' PveHost='$PveHost'"
  }
  Write-Host "DEBUG: Version URI='$($uriVersion.AbsoluteUri)'"
  # Probeer eerst Invoke-RestMethod (betrouwbaarder op Windows PowerShell 5.1)
  try {
    $headers = @{ Authorization = $AuthHeader }
    $resp = Invoke-RestMethod -Uri $uriVersion.AbsoluteUri -Method Get -Headers $headers -ErrorAction Stop
    Write-Host "API OK. (Invoke-RestMethod)"
  } catch {
    Write-Host "Invoke-RestMethod failed: $($_.Exception.Message)" -ForegroundColor Yellow
    # Fallback naar HttpClient
    try {
      $ping = $client.GetAsync($uriVersion.AbsoluteUri).Result
      if ($null -ne $ping -and $ping.IsSuccessStatusCode) {
        Write-Host "API OK. (HttpClient)"
      } else {
        Write-Host "HttpClient also failed or returned non-success. Trying curl.exe fallback..." -ForegroundColor Yellow
        # Try curl.exe fallback
        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
          $curlArgs = @('-k','-sS','-H',"Authorization: $AuthHeader",$uriVersion.AbsoluteUri)
          $curlOut = & curl.exe @curlArgs 2>&1
          if ($LASTEXITCODE -eq 0) {
            Write-Host "API OK. (curl)"
            $UseCurl = $true
          } else {
            Write-Host "curl failed: $curlOut" -ForegroundColor Yellow
            throw "Geen response van API - alle methodes faalden"
          }
        } else {
          throw "Geen curl.exe beschikbaar en beide Invoke-RestMethod/HttpClient faalden"
        }
      }
    } catch {
      throw "Geen response van API (null) - zowel Invoke-RestMethod als HttpClient faalden: $($_.Exception.Message)"
    }
  }
  Write-Host "API OK."
} catch {
  throw $_
}

## 1) Upload ISO (of detecteer bestaande ISO op storage)
Write-Host "1) Upload ISO naar storage '$Storage' op node '$PveNode' (of detecteer bestaande)..."

$localFilename = [System.IO.Path]::GetFileName($IsoPath)
$filename = $localFilename
$skipUpload = $false

# Als gebruiker expliciet IsoFilename opgeeft, gebruik die en sla upload over
if ($IsoFilename -ne "") {
  $filename = $IsoFilename
  Write-Host "IsoFilename parameter opgegeven; gebruik bestaande ISO-naam: $filename (upload wordt overgeslagen)"
  $skipUpload = $true
} else {
  # Probeer de contentlijst van de storage op te halen
  $contentUri = "$($BaseUrl)/nodes/$PveNode/storage/$Storage/content?content=iso"
  try {
    if (-not $UseCurl) {
      $listResp = Invoke-RestMethod -Uri $contentUri -Method Get -Headers @{ Authorization = $AuthHeader } -ErrorAction Stop
      $items = $listResp.data
    } else {
      $curlArgs = @('-k','-sS','-H',"Authorization: $AuthHeader", $contentUri)
      $curlOut = & curl.exe @curlArgs 2>&1
      $json = $curlOut
      $conv = ConvertFrom-Json $json
      $items = $conv.data
    }
  } catch {
    Write-Host "Kon storage content niet ophalen: $($_.Exception.Message)" -ForegroundColor Yellow
    $items = @()
  }

  $found = $false
  foreach ($it in $items) {
    $volid = ($it.volid -as [string])
    $volname = ($it.volname -as [string])
    $path = ($it.path -as [string])
    if ($volid -and $volid.EndsWith("/$localFilename")) { $found = $true; break }
    if ($volname -and $volname -eq $localFilename) { $found = $true; break }
    if ($path -and ($path -like "*${localFilename}")) { $found = $true; break }
  }
  if ($found) {
    $filename = $localFilename
    Write-Host "Gevonden: ISO '$localFilename' bestaat al op storage '$Storage' op node '$PveNode' - upload wordt overgeslagen."
    $skipUpload = $true
  } else {
    Write-Host "ISO niet gevonden op storage; upload wordt uitgevoerd als '$filename'"
    $skipUpload = $false
  }
}

$uriUpload = "$($BaseUrl)/nodes/$PveNode/storage/$Storage/upload"

if (-not $skipUpload) {
  if (-not (Test-Path -LiteralPath $IsoPath)) {
    throw "ISO niet gevonden lokaal: $IsoPath"
  }

  # Gebruik MultipartFormDataContent met FileStream zodat grote ISO's niet volledig in geheugen komen
  $multipart = New-Object System.Net.Http.MultipartFormDataContent
  $multipart.Add((New-Object System.Net.Http.StringContent("iso")), "content")

  if ($UseCurl) {
    Write-Host "Gebruik curl voor upload (curl fallback)." -ForegroundColor Gray
    $curlArgs = @('-k','-sS','-H',"Authorization: $AuthHeader", '-F', "content=iso", '-F', "filename=@$IsoPath;filename=$filename;type=application/octet-stream", $uriUpload)
    $curlOut = & curl.exe @curlArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw "curl upload failed: $curlOut"
    }
    Write-Host "Upload OK. (curl)"
  } else {
    $fileStream = [System.IO.File]::OpenRead($IsoPath)
    try {
      $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
      $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
      $multipart.Add($fileContent, "filename", $filename)

      $response = $client.PostAsync($uriUpload, $multipart).Result
      $uploadTxt = $response.Content.ReadAsStringAsync().Result
      if (-not $response.IsSuccessStatusCode) {
        throw "Upload mislukt: $($response.StatusCode) - $uploadTxt"
      }
      Write-Host "Upload OK."
    } finally {
      $fileStream.Dispose()
    }
  }
} else {
  Write-Host "Upload overslaan (ISO al aanwezig of IsoFilename opgegeven)."
}

if (-not $UploadOnly) {
  # 2) VM aanmaken
  Write-Host "2) VM aanmaken (VMID=$Vmid, NAME=$VmName)..."
  $createUri = "$($BaseUrl)/nodes/$PveNode/qemu"
  $bodyCreate = @{
    vmid   = $Vmid
    name   = $VmName
    cores  = $Cores
    memory = $RamMb
    # Netwerk en disk
    net0   = "virtio,bridge=$Bridge"
    scsihw = "virtio-scsi-pci"
    scsi0  = "$($Storage):${DiskGb}G"
    # ISO mounten op ide2 als cdrom
    ide2   = "$($Storage):iso/$filename,media=cdrom"
    ostype = "l26"
  }
  Invoke-FormPost -Uri $createUri -Body $bodyCreate | Out-Null
  Write-Host "VM create aangevraagd."

  # 3) Boot-order naar cdrom eerst
  Write-Host "3) Boot-order configureren (cdrom eerst)..."
  $configUri = "$($BaseUrl)/nodes/$PveNode/qemu/$Vmid/config"
  Invoke-FormPost -Uri $configUri -Body @{ boot = "order=ide2;scsi0" } | Out-Null

  # 4) VM starten
  Write-Host "4) VM starten..."
  $startUri = "$($BaseUrl)/nodes/$PveNode/qemu/$Vmid/status/start"
  $respStart = $client.PostAsync($startUri, $null).Result
  if (-not $respStart.IsSuccessStatusCode) {
    throw "Start mislukt: $($respStart.StatusCode) - $($respStart.Content.ReadAsStringAsync().Result)"
  }
  Write-Host "Klaar: VM $Vmid ($VmName) gestart met RHEL ISO."
} else {
  Write-Host "UploadOnly gespecificeerd - script stopt na upload."
}
