# Runs Parts C and D of advanced_eval.py, killing zombie Spark executors between runs

function Remove-ZombieExecutors {
    Write-Host "[cleanup] Killing zombie CoarseGrainedExecutorBackend processes..."
    $procs = docker exec threvia-spark-worker ps aux 2>$null |
             Select-String "CoarseGrained" |
             Where-Object { $_ -notmatch "grep" } |
             ForEach-Object { ($_.Line -split '\s+')[1] }
    if ($procs) {
        foreach ($pid in $procs) {
            Write-Host "[cleanup] Killing PID $pid"
            docker exec threvia-spark-worker kill -9 $pid 2>$null
        }
        Start-Sleep -Seconds 6
        Write-Host "[cleanup] Done."
    } else {
        Write-Host "[cleanup] No zombies found."
    }
}

$SS = "/opt/spark/bin/spark-submit"
$M  = "spark://spark-master:7077"
$SCRIPT = "/workspace/backend/ml/advanced_eval.py"

Remove-ZombieExecutors

Write-Host ""
Write-Host "=== START: openset ==="
docker exec threvia-spark-master $SS `
    --master $M `
    --driver-memory 2g `
    --executor-memory 2g `
    $SCRIPT openset
Write-Host "=== DONE: openset ==="

Remove-ZombieExecutors

Write-Host ""
Write-Host "=== START: clusters ==="
docker exec threvia-spark-master $SS `
    --master $M `
    --driver-memory 2g `
    --executor-memory 2g `
    $SCRIPT clusters
Write-Host "=== DONE: clusters ==="

Write-Host ""
Write-Host "ALL DONE"
