# Set-ExecutionPolicy RemoteSigned

# Run
docker run -it --mount type=bind,source=$(pwd)/.app,destination=/app --rm -p 49152:49152/udp archidoc422/netsphere-basictest `
basic -mode receive -directory /app -port 49152 -targetip 192.168.0.1
Write-Output ""

Write-Output "" "Press any key to exit."
Read-Host
