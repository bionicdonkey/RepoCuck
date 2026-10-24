# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Packages.props Directory.Build.props NuGet.config ./
COPY src/RepoCuck.Domain/RepoCuck.Domain.csproj src/RepoCuck.Domain/packages.lock.json src/RepoCuck.Domain/
COPY src/RepoCuck.Debian/RepoCuck.Debian.csproj src/RepoCuck.Debian/packages.lock.json src/RepoCuck.Debian/
COPY src/RepoCuck.Application/RepoCuck.Application.csproj src/RepoCuck.Application/packages.lock.json src/RepoCuck.Application/
COPY src/RepoCuck.Infrastructure/RepoCuck.Infrastructure.csproj src/RepoCuck.Infrastructure/packages.lock.json src/RepoCuck.Infrastructure/
COPY src/RepoCuck.Web/RepoCuck.Web.csproj src/RepoCuck.Web/packages.lock.json src/RepoCuck.Web/
# restore the web project only (the .sln also references test projects that are not copied here)
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet restore src/RepoCuck.Web/RepoCuck.Web.csproj --locked-mode
COPY src ./src
RUN --mount=type=cache,target=/root/.nuget/packages \
    dotnet publish src/RepoCuck.Web/RepoCuck.Web.csproj -c Release -o /out --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS runtime
# The base image already defines the non-root user `app` (UID 1654); reuse it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gnupg xz-utils ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o app -g app -m 0750 /data
WORKDIR /app
COPY --from=build --chown=app:app /out ./
USER app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0 \
    DOTNET_gcServer=0 \
    GNUPGHOME=/data/gnupg \
    Storage__Root=/data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["dotnet", "RepoCuck.Web.dll"]
