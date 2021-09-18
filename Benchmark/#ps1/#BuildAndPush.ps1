# Set-ExecutionPolicy RemoteSigned

cd ../

# Publish
dotnet publish -c Release
Write-Output ""

# Build image
docker build -t archidoc422/netsphere-basictest -f ./#ps1/Dockerfile .
Write-Output ""

# Push image
docker push archidoc422/netsphere-basictest
Write-Output ""

Write-Output "" "Press any key to exit."
Read-Host
