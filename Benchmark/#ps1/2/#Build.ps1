# Set-ExecutionPolicy RemoteSigned

cd ../

# Build image
docker build -t archidoc422/arc-crypto-bench -f ./#ps1/Dockerfile .
Write-Output ""

Write-Output "" "Press any key to exit."
Read-Host
