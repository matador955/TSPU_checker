<#
=========================================================
 TSPU_checker.ps1 - проверка доступности SSH в подсети из двух сетей
 Страница проекта: https://github.com/matador955/TSPU_checker

 Режимы:
   Scan    - прогон проверки. Запускается дважды: из EUR (эталонная сеть) и из RUS (проверяемая сеть).
   Compare - сведение прогонов:
               с -SubnetBase  -> детальный отчёт по одной подсети;
               без -SubnetBase -> сводный отчёт по всем накопленным парам в папке.

 Примеры:
   .\TSPU_checker.ps1 -Mode Scan -Network EUR -SubnetBase 45.131.185  - проверить подсеть, сохранить результаты как эталонные
   .\TSPU_checker.ps1 -Mode Scan -Network RUS -SubnetBase 45.131.185  - проверить подсеть, сохранить результаты как тестируемые
   .\TSPU_checker.ps1 -Mode Compare -SubnetBase 45.131.185            - проанализировать подсеть
   .\TSPU_checker.ps1 -Mode Compare                                   - проаналиировать все накопленные в папке результаты
=========================================================
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Scan', 'Compare')]
    [string]$Mode,

    [ValidateSet('EUR', 'RUS')]
    [string]$Network,

    [string]$SubnetBase,

    [switch]$Force
)

# =========================================================
# НАСТРОЙКИ (правятся при необходимости)
# =========================================================
$Count     = 20               # Сколько случайных IP из общего числа (255) проверять. Больше = точнее картина, но дольше прогон.
$SSHPorts  = @(22, 222, 2222) # Порты SSH для последовательной проверки
$TimeoutMs = 400              # Таймаут на пинг и на КАЖДЫЙ порт (мс). Меньше = быстрее, но далёкие хосты могут не успеть ответить.
# =========================================================

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Utf8Bom   = New-Object System.Text.UTF8Encoding($true)   # для текстовых логов
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)  # для JSON

# ---------- Вспомогательные функции ----------

function Get-Percent([int]$Part, [int]$Whole) {
    if ($Whole -gt 0) { [math]::Round(($Part / $Whole) * 100, 1) } else { 0 }
}

# Проверка одного хоста: пинг + SSH 
function Test-TargetHost {
    param([string]$IP)

    $pingSuccess = $false
    $openPort    = $null

    try {
        $ping  = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IP, $TimeoutMs)
        if ($reply.Status -eq 'Success') { $pingSuccess = $true }
    } catch {
        $pingSuccess = $false
    }

    foreach ($port in $SSHPorts) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $asyncResult = $tcpClient.BeginConnect($IP, $port, $null, $null)
            $waitHandle  = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if ($waitHandle -and $tcpClient.Connected) {
                $tcpClient.EndConnect($asyncResult)
                $openPort = $port
            }
        } catch {
        } finally {
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
        if ($openPort) { break }
    }

    [PSCustomObject]@{
        IP       = $IP
        IsPingOK = $pingSuccess
        IsSSHOK  = [bool]$openPort
        SSHPort  = $openPort
    }
}

# =========================================================
# РЕЖИМ SCAN
# =========================================================
function Invoke-Scan {

    if (-not $Network)    { throw "Для режима Scan обязателен параметр -Network (EUR или RUS)." }
    if (-not $SubnetBase) { throw "Для режима Scan обязателен параметр -SubnetBase (например 45.131.185)." }

    $targetsPath = Join-Path $ScriptDir "targets_$SubnetBase.txt"
    $resultPath  = Join-Path $ScriptDir "result_${SubnetBase}_$Network.json"
    $logPath     = Join-Path $ScriptDir "${SubnetBase}_$Network.txt"

    # Защита от перезаписи результата
    if ((Test-Path $resultPath) -and (-not $Force)) {
        throw "Файл результата уже существует: $resultPath`n" +
              "Повторный запуск затрёт данные. Используйте -Force, если это осознанно."
    }

    # Лог для глаз
    [System.IO.File]::WriteAllText($logPath, "", $Utf8Bom)
    function Write-Log {
        param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::White)
        Write-Host $Message -ForegroundColor $Color
        [System.IO.File]::AppendAllText($logPath, $Message + [Environment]::NewLine, $Utf8Bom)
    }

    # Список целей: читаем существующий или генерируем новый
    if (Test-Path $targetsPath) {
        $IPList = Get-Content -Path $targetsPath | Where-Object { $_.Trim() -ne "" }
        Write-Log "Список целей прочитан из файла: $targetsPath ($($IPList.Count) шт.)"
    } else {
        $IPList = 1..254 | ForEach-Object { "$SubnetBase.$_" } | Get-Random -Count $Count
        $IPList | Out-File -FilePath $targetsPath -Encoding utf8 -Force
        Write-Log "Сгенерирован новый список целей: $targetsPath ($($IPList.Count) шт.)"
    }

    Write-Log "========================================================="
    Write-Log " Прогон: сеть $Network | подсеть $SubnetBase.0/24"
    Write-Log " Время : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "========================================================="

    $Results = @()
    foreach ($ip in $IPList) {
        $r = Test-TargetHost -IP $ip
        $Results += $r

        $pingText = if ($r.IsPingOK) { "Пинг ОК " } else { "Пинг НЕТ" }
        if ($r.IsSSHOK -and $r.IsPingOK) {
            Write-Log "[+] $ip : $pingText | SSH ОТКРЫТ (порт $($r.SSHPort))" -Color Green
        } elseif ($r.IsSSHOK) {
            Write-Log "[+] $ip : $pingText | SSH ОТКРЫТ (порт $($r.SSHPort)) (ICMP закрыт)" -Color Cyan
        } elseif ($r.IsPingOK) {
            Write-Log "[!] $ip : $pingText | SSH НЕДОСТУПЕН" -Color Yellow
        } else {
            Write-Log "[-] $ip : $pingText | SSH НЕДОСТУПЕН" -Color Gray
        }
    }

    # Статистика прогона
    $totalCount = $Results.Count
    $pingCount  = @($Results | Where-Object { $_.IsPingOK }).Count
    $sshCount   = @($Results | Where-Object { $_.IsSSHOK }).Count

    Write-Log ""
    Write-Log "========================================================="
    Write-Log "                СТАТИСТИКА ПРОГОНА ($Network)"
    Write-Log "========================================================="
    Write-Log "Всего проверено IP : $totalCount"
    Write-Log "Ответили на пинг   : $pingCount ($(Get-Percent $pingCount $totalCount)%)"
    Write-Log "Ответили на SSH    : $sshCount ($(Get-Percent $sshCount $totalCount)%)"
    Write-Log "========================================================="

    # Машиночитаемый результат
    $payload = [PSCustomObject]@{
        Network     = $Network
        SubnetBase  = $SubnetBase
        Timestamp   = (Get-Date -Format 'o')
        TargetCount = $totalCount
        Results     = $Results
    }
    $json = $payload | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($resultPath, $json, $Utf8NoBom)

    Write-Host ""
    Write-Host "Готово. Результат: $resultPath" -ForegroundColor Cyan
    Write-Host "Лог      : $logPath" -ForegroundColor Cyan
}

# =========================================================
# РЕЖИМ COMPARE
# =========================================================
function Invoke-Compare {
    if ($SubnetBase) { Invoke-CompareOne } else { Invoke-CompareAll }
}

# Общая логика сравнения одной пары прогонов. 
function Compare-Pair {
    param([string]$EurPath, [string]$RusPath)

    $eur = Get-Content -Path $EurPath -Raw | ConvertFrom-Json
    $rus = Get-Content -Path $RusPath -Raw | ConvertFrom-Json

    $eurByIp = @{}; foreach ($r in $eur.Results) { $eurByIp[$r.IP] = $r }
    $rusByIp = @{}; foreach ($r in $rus.Results) { $rusByIp[$r.IP] = $r }

    $onlyEur = @($eur.Results.IP | Where-Object { -not $rusByIp.ContainsKey($_) })
    $onlyRus = @($rus.Results.IP | Where-Object { -not $eurByIp.ContainsKey($_) })

    $rows = @()
    foreach ($r in $eur.Results) {
        if (-not $rusByIp.ContainsKey($r.IP)) { continue }
        $e = $r
        $u = $rusByIp[$r.IP]

        $blocked  = ($e.IsSSHOK -and (-not $u.IsSSHOK))        # цель проверки: SSH был в EUR, пропал в RUS
        $pingLost = ($e.IsPingOK -and (-not $u.IsPingOK))      # пинг был в EUR, пропал в RUS (RUS блокирует и пинг)
        $pingSpam = ((-not $e.IsPingOK) -and $u.IsPingOK)      # пинга не было в EUR, но есть в RUS -> блокировка за спам

        $noServer = (-not $e.IsPingOK) -and (-not $u.IsPingOK) -and `
                    (-not $e.IsSSHOK) -and (-not $u.IsSSHOK)  # глухо со всех сторон

        $verdict =
            if ($blocked)                              { "SSH заблокирован" }
            elseif ($e.IsSSHOK -and $u.IsSSHOK)        { "доступен в обеих" }
            elseif ((-not $e.IsSSHOK) -and $u.IsSSHOK) { "SSH только в RUS" }
            elseif ($noServer)                         { "нет сервера" }
            else                                       { "SSH недоступен" }

        $rows += [PSCustomObject]@{
            IP        = $e.IP
            SSH_EUR   = if ($e.IsSSHOK)  { "да ($($e.SSHPort))" } else { "нет" }
            SSH_RUS   = if ($u.IsSSHOK)  { "да ($($u.SSHPort))" } else { "нет" }
            Ping_EUR  = if ($e.IsPingOK) { "да" } else { "нет" }
            Ping_RUS  = if ($u.IsPingOK) { "да" } else { "нет" }
            Вердикт   = $verdict
            _blocked  = $blocked
            _pingLost = $pingLost
            _pingSpam = $pingSpam
            _baseSSH  = $e.IsSSHOK
        }
    }

    [PSCustomObject]@{
        Rows     = $rows
        OnlyEur  = $onlyEur
        OnlyRus  = $onlyRus
        EurTime  = $eur.Timestamp
        RusTime  = $rus.Timestamp
        Matched  = $rows.Count
        BaseSSH  = @($rows | Where-Object { $_._baseSSH }).Count
        Blocked  = @($rows | Where-Object { $_._blocked }).Count
        PingLost = @($rows | Where-Object { $_._pingLost }).Count
        PingSpam = @($rows | Where-Object { $_._pingSpam }).Count
    }
}

# --- Compare с -SubnetBase: детальный отчёт по одной подсети ---
function Invoke-CompareOne {

    $eurPath     = Join-Path $ScriptDir "result_${SubnetBase}_EUR.json"
    $rusPath     = Join-Path $ScriptDir "result_${SubnetBase}_RUS.json"
    $comparePath = Join-Path $ScriptDir "compare_$SubnetBase.txt"

    if (-not (Test-Path $eurPath)) { throw "Нет файла эталонного прогона: $eurPath" }
    if (-not (Test-Path $rusPath)) { throw "Нет файла проверяемого прогона: $rusPath" }

    $cmp = Compare-Pair -EurPath $eurPath -RusPath $rusPath

    [System.IO.File]::WriteAllText($comparePath, "", $Utf8Bom)
    function Write-Cmp {
        param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::White)
        Write-Host $Message -ForegroundColor $Color
        [System.IO.File]::AppendAllText($comparePath, $Message + [Environment]::NewLine, $Utf8Bom)
    }

    Write-Cmp "========================================================="
    Write-Cmp " Сравнение подсети $SubnetBase.0/24"
    Write-Cmp " Эталон EUR : $($cmp.EurTime)"
    Write-Cmp " Тест   RUS : $($cmp.RusTime)"
    Write-Cmp "========================================================="

    if ($cmp.OnlyEur.Count -gt 0 -or $cmp.OnlyRus.Count -gt 0) {
        Write-Cmp "ВНИМАНИЕ: наборы целей в прогонах различаются!" -Color Red
        if ($cmp.OnlyEur.Count) { Write-Cmp "  Только в EUR: $($cmp.OnlyEur -join ', ')" -Color Red }
        if ($cmp.OnlyRus.Count) { Write-Cmp "  Только в RUS: $($cmp.OnlyRus -join ', ')" -Color Red }
        Write-Cmp "  Сравнение ведётся только по общим адресам." -Color Red
        Write-Cmp ""
    }

    Write-Cmp "Всего сопоставлено IP           : $($cmp.Matched)"
    Write-Cmp "Имели SSH в EUR (база)          : $($cmp.BaseSSH)"
    Write-Cmp ""
    Write-Cmp "SSH ЗАБЛОКИРОВАНО в RUS         : $($cmp.Blocked) из $($cmp.BaseSSH) ($(Get-Percent $cmp.Blocked $cmp.BaseSSH)% от базы)" -Color Red
    Write-Cmp ""
    Write-Cmp "Пинг был в EUR, нет в RUS      : $($cmp.PingLost)" -Color $(if ($cmp.PingLost -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Cmp "Пинга не было в EUR, есть в RUS: $($cmp.PingSpam)" -Color $(if ($cmp.PingSpam -gt 0) { 'Red' } else { 'Gray' })
    if ($cmp.PingSpam -gt 0) {
        Write-Cmp "  ^ подозрение на блокировку за спам" -Color Red
    }
    Write-Cmp "========================================================="

    Write-Cmp ""
    Write-Cmp "Детализация:"
    $table = $cmp.Rows |
        Select-Object IP, SSH_EUR, SSH_RUS, Ping_EUR, Ping_RUS, Вердикт |
        Format-Table -AutoSize | Out-String -Width 200
    Write-Cmp $table.TrimEnd()

    Write-Host ""
    Write-Host "Готово. Отчёт сравнения: $comparePath" -ForegroundColor Cyan
}

# --- Compare без -SubnetBase: сводка по всем парам result_*_EUR/RUS.json в папке ---
function Invoke-CompareAll {

    $summaryPath = Join-Path $ScriptDir "compare_ALL.txt"

    # Группируем найденные result-файлы по подсети (compare_*.txt намеренно не трогаем)
    $subnets = @{}
    foreach ($f in (Get-ChildItem -Path $ScriptDir -Filter "result_*.json" -File)) {
        $core = $f.BaseName -replace '^result_', ''   # напр. "45.131.185_EUR"
        $idx  = $core.LastIndexOf('_')
        if ($idx -lt 1) { continue }
        $sub = $core.Substring(0, $idx)
        $net = $core.Substring($idx + 1)
        if ($net -ne 'EUR' -and $net -ne 'RUS') { continue }
        if (-not $subnets.ContainsKey($sub)) { $subnets[$sub] = @{} }
        $subnets[$sub][$net] = $f.FullName
    }

    if ($subnets.Count -eq 0) { throw "В папке $ScriptDir нет ни одного файла result_*.json." }

    [System.IO.File]::WriteAllText($summaryPath, "", $Utf8Bom)
    function Write-Cmp {
        param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::White)
        Write-Host $Message -ForegroundColor $Color
        [System.IO.File]::AppendAllText($summaryPath, $Message + [Environment]::NewLine, $Utf8Bom)
    }

    Write-Cmp "========================================================="
    Write-Cmp " СВОДНЫЙ ОТЧЁТ по всем подсетям в папке"
    Write-Cmp " Папка: $ScriptDir"
    Write-Cmp "========================================================="

    $summary = @()
    $skipped = @()
    foreach ($sub in ($subnets.Keys | Sort-Object)) {
        $pair = $subnets[$sub]
        if (-not $pair.ContainsKey('EUR') -or -not $pair.ContainsKey('RUS')) {
            $have = ($pair.Keys | Sort-Object) -join '+'
            $skipped += "$sub (есть только $have)"
            continue
        }
        $cmp = Compare-Pair -EurPath $pair['EUR'] -RusPath $pair['RUS']
        $summary += [PSCustomObject]@{
            Подсеть  = $sub
            База     = $cmp.BaseSSH
            Заблок   = $cmp.Blocked
            Процент  = "$(Get-Percent $cmp.Blocked $cmp.BaseSSH)%"
            _base    = $cmp.BaseSSH
            _blocked = $cmp.Blocked
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Cmp "Пропущены (нет пары EUR+RUS):" -Color Yellow
        foreach ($s in $skipped) { Write-Cmp "  - $s" -Color Yellow }
        Write-Cmp ""
    }

    if ($summary.Count -eq 0) { throw "Не найдено ни одной полной пары прогонов (EUR+RUS)." }

    Write-Cmp "Сведено подсетей: $($summary.Count)"
    Write-Cmp ""

    $table = $summary |
        Select-Object Подсеть, База, Заблок, Процент |
        Format-Table -AutoSize | Out-String -Width 200
    Write-Cmp $table.TrimEnd()

    $totalBase    = ($summary | Measure-Object -Property _base -Sum).Sum
    $totalBlocked = ($summary | Measure-Object -Property _blocked -Sum).Sum
    Write-Cmp ""
    Write-Cmp "---------------------------------------------------------"
    Write-Cmp "ИТОГО: SSH заблокировано $totalBlocked из $totalBase ($(Get-Percent $totalBlocked $totalBase)% от общей базы)" -Color Red
    Write-Cmp "========================================================="

    Write-Host ""
    Write-Host "Готово. Сводный отчёт: $summaryPath" -ForegroundColor Cyan
}

# =========================================================
# ТОЧКА ВХОДА
# =========================================================
try {
    switch ($Mode) {
        'Scan'    { Invoke-Scan }
        'Compare' { Invoke-Compare }
    }
} catch {
    Write-Host "ОШИБКА: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
