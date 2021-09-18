# Set-ExecutionPolicy RemoteSigned

cd ../

# Publish
dotnet publish -c Release
Write-Output ""

# Build image
docker build -t archidoc422/arc-crypto-bench -f ./#ps1/Dockerfile .
Write-Output ""

Write-Output "" "Press any key to exit."
Read-Host
