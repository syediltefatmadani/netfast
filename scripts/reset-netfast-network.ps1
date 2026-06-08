# NetFast / FocusLock emergency network reset — removes only NetFast-managed settings.
# Run as Administrator for full effect.

$ErrorActionPreference = 'Continue'
Write-Host '[NetFast Reset] Starting network reset...'

function Remove-NetFastFirewallRules {
  $removed = 0
  $prefixes = @('NetFast-DNS-', 'NetFast-Exempt-', 'NetFast-Dev-', 'NetFast Block ')
  $rules = netsh advfirewall firewall show rule name=all | Select-String 'Rule Name:' | ForEach-Object {
    $_.Line -replace 'Rule Name:\s*', '' | ForEach-Object { $_.Trim() }
  }
  foreach ($name in $rules) {
    foreach ($prefix in $prefixes) {
      if ($name -like "$prefix*") {
        netsh advfirewall firewall delete rule name="$name" | Out-Null
        Write-Host "[NetFast Reset] Removed firewall rule: $name"
        $removed++
        break
      }
    }
  }
  Write-Host "[NetFast Reset] Firewall rules removed: $removed"
}

function Reset-AdapterDnsToDhcp {
  $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -notmatch 'Loopback|Software Loopback|Microsoft Loopback' -and
    $_.Name -notmatch 'Loopback'
  }
  foreach ($adapter in $adapters) {
    $alias = $adapter.Name
    try {
      Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue
      netsh interface ipv6 set dnsservers name="$alias" source=dhcp | Out-Null
      Write-Host "[NetFast Reset] Reset DNS to DHCP on: $alias"
    } catch {
      Write-Host "[NetFast Reset] Could not reset DNS on ${alias}: $($_.Exception.Message)"
    }
  }
}

function Enable-Ipv6Bindings {
  $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -notmatch 'Loopback|Software Loopback|Microsoft Loopback'
  }
  foreach ($adapter in $adapters) {
    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    if ($binding -and -not $binding.Enabled) {
      Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue
      Write-Host "[NetFast Reset] Re-enabled IPv6 on: $($adapter.Name)"
    }
  }
}

function Remove-NetFastNrptRules {
  $prefix = 'NetFast-Mongo-'
  $rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "$prefix*" -or $_.Comment -like "$prefix*"
  }
  foreach ($rule in $rules) {
    $ruleId = @($rule.Name)[0]
    if ($ruleId) {
      Remove-DnsClientNrptRule -Name $ruleId -Force -ErrorAction SilentlyContinue
      Write-Host "[NetFast Reset] Removed NRPT rule: $($rule.DisplayName)"
    }
  }
}

function Remove-CleanBrowsingDoh {
  $cleanBrowsing = @('185.228.168.168', '185.228.169.168', '2a0d:2a00:1::', '2a0d:2a00:2::')
  Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object {
    $cleanBrowsing -contains $_.ServerAddress
  } | ForEach-Object {
    Remove-DnsClientDohServerAddress -ServerAddress $_.ServerAddress -ErrorAction SilentlyContinue
    Write-Host "[NetFast Reset] Removed DoH server: $($_.ServerAddress)"
  }
}

function Remove-ChromiumSecureDnsPolicies {
  $keys = @(
    'HKCU\Software\Policies\Google\Chrome',
    'HKCU\Software\Policies\Microsoft\Edge',
    'HKCU\Software\Policies\BraveSoftware\Brave',
    'HKLM\Software\Policies\Google\Chrome',
    'HKLM\Software\Policies\Microsoft\Edge'
  )
  foreach ($key in $keys) {
    foreach ($valueName in @('DnsOverHttpsMode', 'DnsOverHttpsTemplates')) {
      reg delete "$key" /v $valueName /f 2>$null | Out-Null
    }
  }
  Write-Host '[NetFast Reset] Removed NetFast Chromium Secure DNS policies'
}

function Remove-FocuslockHostsSections {
  $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
  if (-not (Test-Path $hostsPath)) { return }
  $content = Get-Content $hostsPath -Raw
  $markers = @(
    @('# focuslock-block-begin', '# focuslock-block-end'),
    @('# focuslock-mongo-begin', '# focuslock-mongo-end')
  )
  $changed = $false
  foreach ($pair in $markers) {
    $begin = $pair[0]
    $end = $pair[1]
    if ($content -match [regex]::Escape($begin) -and $content -match [regex]::Escape($end)) {
      $pattern = "(?s)$([regex]::Escape($begin)).*$([regex]::Escape($end))"
      $content = $content -replace $pattern, ''
      $changed = $true
    }
  }
  if ($changed) {
    Set-Content -Path $hostsPath -Value $content.TrimEnd() -NoNewline
    Write-Host '[NetFast Reset] Removed FocusLock hosts sections'
  }
}

function Flush-Dns {
  ipconfig /flushdns | Out-Null
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  Write-Host '[NetFast Reset] DNS cache flushed'
}

Remove-NetFastFirewallRules
Reset-AdapterDnsToDhcp
Enable-Ipv6Bindings
Remove-NetFastNrptRules
Remove-CleanBrowsingDoh
Remove-ChromiumSecureDnsPolicies
Remove-FocuslockHostsSections
Flush-Dns

Write-Host '[NetFast Reset] Complete. Reboot if connectivity issues persist.'
