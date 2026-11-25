$cert = New-SelfSignedCertificate -DnsName "localhost","ObjAsm TLS Test" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec KeyExchange `
    -KeyLength 2048 -NotAfter (Get-Date).AddYears(10) `
    -FriendlyName "ObjAsm TLS Test" -Subject "CN=ObjAsm TLS Test"

Write-Host "Certificate created. Thumbprint:" $cert.Thumbprint

$pwd = ConvertTo-SecureString -String "test" -Force -AsPlainText
$pfxPath = Join-Path $PSScriptRoot "ObjAsmTLSTest.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null

Write-Host "PFX exported to:" $pfxPath
