FROM mcr.microsoft.com/dotnet/sdk:6.0
WORKDIR /src
COPY . .
RUN dotnet restore

RUN dotnet build "Benchmark/Benchmark.csproj" -c Release -o /src/bin
RUN dotnet publish "Benchmark/Benchmark.csproj" -c Release -o /src/bin/publish

WORKDIR /src/bin/Release/net6.0/publish/
ENTRYPOINT ["dotnet", "Benchmark.dll"]
