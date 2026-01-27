param(
    [string]$s = "auth"
)

Write-Host "Using suffix: $s" -ForegroundColor Green

docker-compose down -v
if ($?) {
    $imageName = "sso_$s"
    Write-Host "Removing image: $imageName" -ForegroundColor Yellow
    docker rmi -f $imageName
}
if ($?) {
    docker-compose build --no-cache
}
if ($?) {
    docker-compose up -d
}