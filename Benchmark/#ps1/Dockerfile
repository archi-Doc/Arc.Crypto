FROM mcr.microsoft.com/dotnet/sdk:6.0
COPY bin/Release/net6.0/publish/ App/
WORKDIR /App
ENTRYPOINT ["dotnet", "Benchmark.dll"]
