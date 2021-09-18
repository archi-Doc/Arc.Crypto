# Set-ExecutionPolicy RemoteSigned

# Build image
docker build -t archidoc422/arc-crypto-bench -f ./Dockerfile .
Write-Output ""

Write-Output "" "Press any key to exit."
Read-Host
