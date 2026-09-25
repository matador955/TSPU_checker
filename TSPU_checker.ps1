<#
=========================================================
 TSPU_checker.ps1 - проверка доступности SSH в подсети из двух сетей
 Страница проекта: https://github.com/matador955/TSPU_checker

 Режимы:
   Scan    - прогон проверки. Запускается дважды: из EUR (эталон) и из RUS (проверяемая).
   Compare - сведение прогонов:
               с -SubnetBase  -> детальный отчёт по одной подсети;
               без -SubnetBase -> сводный отчёт по всем накопленным парам в папке.

 Примеры:
   .\TSPU_checker.ps1 -Mode Scan -Network EUR -SubnetBase 45.131.185
   .\TSPU_checker.ps1 -Mode Scan -Network RUS -SubnetBase 45.131.185
   .\TSPU_checker.ps1 -Mode Scan -Network RUS -SubnetBase 45.131.185 -CheckHTTP yes
   .\TSPU_checker.ps1 -Mode Compare -SubnetBase 45.131.185
   .\TSPU_checker.ps1 -Mode Compare
=========================================================
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Scan', 'Compare')]
    [string]$Mode,

    [ValidateSet('EUR', 'RUS')]
    [string]$Network,

    [string]$SubnetBase,

    [ValidateSet('yes', 'no')]
    [string]$CheckHTTP = 'no',

    [switch]$Force
)

# =========================================================
# НАСТРОЙКИ (правятся здесь при необходимости)
# =========================================================
$Count       = 30               # Сколько случайных IP из /24 проверять. Больше = точнее картина, но дольше прогон.
$SSHPorts    = @(22, 222, 2222) # Порты SSH для последовательной проверки
$TimeoutMs   = 400              # Таймаут на пинг и на установку TCP-соединения (мс). Быстро отсекает мёртвые адреса.
$WebExchangeMs = 2500           # Таймаут на веб-ОБМЕН (TLS-рукопожатие на 443, чтение ответа на 80). Больше $TimeoutMs, т.к. рукопожатие занимает несколько кругов; на медленных/дальних хостах увеличьте.
# =========================================================

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Utf8Bom   = New-Object System.Text.UTF8Encoding($true)   # для текстовых логов
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)  # для JSON

# ---------- Вспомогательные функции ----------

function Get-Percent([int]$Part, [int]$Whole) {
    if ($Whole -gt 0) { [math]::Round(($Part / $Whole) * 100, 1) } else { 0 }
}

# Текст веб-исхода для построчного лога Scan.
function Format-WebOutcome {
    param($Https, $Http)
    if ($null -eq $Https) { return $null }                      # веб не проверялся
    if ($Https -eq 'open') { return "HTTPS открыт" }
    if ($Https -eq 'tcp_only') {
        # 443 дал tcp_only -> 80 не проверялся (проверяем только когда 443 промолчал полностью)
        return "HTTPS TCP блок"
    }
    # $Https -eq 'closed' -> смотрим 80
    switch ($Http) {
        'open'     { return "HTTPS закрыт | HTTP открыт" }
        'tcp_only' { return "HTTPS закрыт | HTTP TCP блок" }
        default    { return "веб закрыт (443/80)" }
    }
}

# Короткое значение веб-статуса для колонок таблицы Compare: открыт / tcp блок / закрыт / —
function Format-WebCell {
    param($Https, $Http)
    if ($null -eq $Https) { return "—" }                        # веб не проверялся
    if ($Https -eq 'open') { return "открыт" }
    if ($Https -eq 'tcp_only') { return "tcp блок" }
    switch ($Http) {
        'open'     { return "открыт" }
        'tcp_only' { return "tcp блок" }
        default    { return "закрыт" }
    }
}

# Итоговый веб-статус хоста одним словом: open / tcp_only / closed / $null (не проверялся).
# 443 приоритетнее; 80 смотрим только если 443 не 'open'.
function Get-WebStatus {
    param($Https, $Http)
    if ($null -eq $Https) { return $null }
    if ($Https -eq 'open') { return 'open' }
    if ($Https -eq 'tcp_only') { return 'tcp_only' }
    # 443 closed
    if ($null -ne $Http) { return $Http }   # open / tcp_only / closed
    return 'closed'
}

# Статистика времени пинга по набору значений (мс). Возвращает среднее, σ, CV и N.
function Get-PingStats {
    param([double[]]$Values)

    $n = @($Values).Count
    if ($n -eq 0) {
        return [PSCustomObject]@{ N = 0; Avg = $null; Std = $null; CV = $null }
    }
    $avg = ($Values | Measure-Object -Average).Average
    if ($n -gt 1) {
        $sumSq = 0.0
        foreach ($v in $Values) { $sumSq += [math]::Pow($v - $avg, 2) }
        $std = [math]::Sqrt($sumSq / ($n - 1))   # выборочное СКО
    } else {
        $std = 0.0
    }
    $cv = if ($avg -ne 0) { ($std / $avg) * 100 } else { 0 }

    [PSCustomObject]@{
        N   = $n
        Avg = [math]::Round($avg, 1)
        Std = [math]::Round($std, 1)
        CV  = [math]::Round($cv, 1)
    }
}

# Текст блока статистики пинга (набор строк) для отчёта Compare.
function Get-PingBlockLines {
    param([string]$Label, $Stat)
    if ($Stat.N -gt 0) {
        return @(
            "$Label (по ответившим, N=$($Stat.N)): среднее $($Stat.Avg) мс | СКО $($Stat.Std) мс | CV $($Stat.CV)%"
        )
    } else {
        return @("$Label : нет данных (никто не ответил на пинг)")
    }
}

# Проверка одного веб-порта. Возвращает 'open' / 'tcp_only' / 'closed'.
#  443: успехом считается состоявшееся TLS-рукопожатие.
#  80 : успехом считается получение любых байт в ответ на "GET /".
# Три рубежа от зависаний: таймаут соединения, ReadTimeout/WriteTimeout, гарантированный finally.
function Test-WebPort {
    param([string]$IP, [int]$Port)

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $result    = 'closed'
    try {
        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $connected   = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($connected -and $tcpClient.Connected)) {
            return 'closed'
        }
        $tcpClient.EndConnect($asyncResult)

        # Соединение установлено -> дальше обмен, по умолчанию считаем tcp_only
        $result = 'tcp_only'

        if ($Port -eq 443) {
            # TLS-рукопожатие СИНХРОННО и с явным TLS 1.2/1.3.
            # Синхронный вызов важен: колбэк проверки сертификата (PowerShell-скриптблок) должен
            # выполняться на основном потоке. В асинхронном режиме он вызывается на потоке пула,
            # где нет Runspace, и рукопожатие мгновенно падает. От зависания страхует ReadTimeout.
            $proto = [System.Security.Authentication.SslProtocols]::Tls12
            try { $proto = $proto -bor [System.Security.Authentication.SslProtocols]::Tls13 } catch {}

            $netStream = $tcpClient.GetStream()
            $netStream.ReadTimeout  = $WebExchangeMs
            $netStream.WriteTimeout = $WebExchangeMs
            $ssl = New-Object System.Net.Security.SslStream(
                $netStream, $false,
                ([System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true })
            )
            try {
                $ssl.AuthenticateAsClient($IP, $null, $proto, $false)   # бросит исключение при неудаче/таймауте чтения
                $result = 'open'
            } catch {
                $result = 'tcp_only'
            } finally {
                $ssl.Dispose()
            }
        } else {
            # Порт 80: шлём минимальный GET и ждём хоть какой-то ответ (бюджет $WebExchangeMs на чтение)
            $netStream = $tcpClient.GetStream()
            $netStream.ReadTimeout  = $WebExchangeMs
            $netStream.WriteTimeout = $TimeoutMs
            try {
                $request = "GET / HTTP/1.0`r`nHost: $IP`r`nConnection: close`r`n`r`n"
                $bytes   = [System.Text.Encoding]::ASCII.GetBytes($request)
                $netStream.Write($bytes, 0, $bytes.Length)
                $buffer  = New-Object byte[] 64
                $read    = $netStream.Read($buffer, 0, $buffer.Length)
                if ($read -gt 0) { $result = 'open' }
            } catch {
                $result = 'tcp_only'
            }
        }
    } catch {
        # ошибка на этапе соединения трактуется как closed, если оно не успело установиться
    } finally {
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
    return $result
}

# Проверка одного хоста: пинг + SSH (SSH проверяется всегда, независимо от пинга).
# Веб (443/80) — только при $CheckHTTP='yes' и только если хост не полностью глухой.
function Test-TargetHost {
    param([string]$IP)

    $pingSuccess = $false
    $pingMs      = $null
    $openPort    = $null
    $httpsStatus = $null
    $httpStatus  = $null

    try {
        $ping  = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IP, $TimeoutMs)
        if ($reply.Status -eq 'Success') {
            $pingSuccess = $true
            $pingMs      = [double]$reply.RoundtripTime
        }
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

    # Веб-проверка: только по запросу и только если есть хоть какой-то признак жизни
    if ($CheckHTTP -eq 'yes' -and ($pingSuccess -or $openPort)) {
        $httpsStatus = Test-WebPort -IP $IP -Port 443
        if ($httpsStatus -eq 'closed') {
            $httpStatus = Test-WebPort -IP $IP -Port 80   # 80 только если на 443 нет даже TCP
        }
    }

    [PSCustomObject]@{
        IP       = $IP
        IsPingOK = $pingSuccess
        PingMs   = $pingMs
        IsSSHOK  = [bool]$openPort
        SSHPort  = $openPort
        Https    = $httpsStatus
        Http     = $httpStatus
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
    Write-Log " Проверка HTTP/HTTPS: $CheckHTTP"
    Write-Log "========================================================="

    $Results = @()
    foreach ($ip in $IPList) {
        $r = Test-TargetHost -IP $ip
        $Results += $r

        # Базовая часть строки: пинг + SSH
        $pingText = if ($r.IsPingOK) { "Пинг ОК " } else { "Пинг НЕТ" }
        if ($r.IsSSHOK -and $r.IsPingOK) {
            $line = "[+] $ip : $pingText | SSH ОТКРЫТ (порт $($r.SSHPort))"; $color = 'Green'
        } elseif ($r.IsSSHOK) {
            $line = "[+] $ip : $pingText | SSH ОТКРЫТ (порт $($r.SSHPort)) (ICMP закрыт)"; $color = 'Cyan'
        } elseif ($r.IsPingOK) {
            $line = "[!] $ip : $pingText | SSH НЕДОСТУПЕН"; $color = 'Yellow'
        } else {
            $line = "[-] $ip : $pingText | SSH НЕДОСТУПЕН"; $color = 'Gray'
        }

        # Веб-часть (если проверялась)
        if ($CheckHTTP -eq 'yes') {
            $webText = Format-WebOutcome -Https $r.Https -Http $r.Http
            if ($webText) { $line = "$line | $webText" }
        }

        Write-Log $line -Color $color
    }

    # ---- Статистика прогона ----
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

    # Время пинга (по ответившим)
    $pingValues = @($Results | Where-Object { $_.IsPingOK -and $null -ne $_.PingMs } | ForEach-Object { [double]$_.PingMs })
    $ps = Get-PingStats -Values $pingValues
    Write-Log ""
    if ($ps.N -gt 0) {
        Write-Log "Время пинга (по ответившим, N=$($ps.N)):"
        Write-Log "  среднее : $($ps.Avg) мс"
        Write-Log "  СКО (s) : $($ps.Std) мс"
        Write-Log "  CV      : $($ps.CV)%"
    } else {
        Write-Log "Время пинга: нет данных (никто не ответил на пинг)"
    }

    # Веб-порты
    if ($CheckHTTP -eq 'yes') {
        $webChecked = @($Results | Where-Object { $null -ne $_.Https })
        $httpsOpen  = @($webChecked | Where-Object { $_.Https -eq 'open' }).Count
        $httpOpen   = @($webChecked | Where-Object { $_.Http  -eq 'open' }).Count
        $tcpOnly    = @($webChecked | Where-Object { $_.Https -eq 'tcp_only' -or $_.Http -eq 'tcp_only' }).Count
        $webClosed  = @($webChecked | Where-Object {
                          ($_.Https -eq 'closed') -and ($null -eq $_.Http -or $_.Http -eq 'closed')
                        }).Count
        Write-Log ""
        Write-Log "Веб-порты (проверено хостов: $($webChecked.Count)):"
        Write-Log "  443 (HTTPS) открыт     : $httpsOpen"
        Write-Log "  80  (HTTP)  открыт     : $httpOpen"
        Write-Log "  TCP есть, обмен срезан : $tcpOnly"
        Write-Log "  полностью закрыто      : $webClosed"
    }
    Write-Log "========================================================="

    # ---- Машиночитаемый результат ----
    $payload = [PSCustomObject]@{
        Network     = $Network
        SubnetBase  = $SubnetBase
        Timestamp   = (Get-Date -Format 'o')
        TargetCount = $totalCount
        CheckHTTP   = $CheckHTTP
        TimeoutMs   = $TimeoutMs
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

# Общая логика сравнения одной пары прогонов. Ничего не выводит и не пишет — только считает.
function Compare-Pair {
    param([string]$EurPath, [string]$RusPath)

    $eur = Get-Content -Path $EurPath -Raw | ConvertFrom-Json
    $rus = Get-Content -Path $RusPath -Raw | ConvertFrom-Json

    # Веб-анализ возможен только если ОБА прогона делались с -CheckHTTP yes
    $webAvailable = ($eur.CheckHTTP -eq 'yes') -and ($rus.CheckHTTP -eq 'yes')

    $eurByIp = @{}; foreach ($r in $eur.Results) { $eurByIp[$r.IP] = $r }
    $rusByIp = @{}; foreach ($r in $rus.Results) { $rusByIp[$r.IP] = $r }

    $onlyEur = @($eur.Results.IP | Where-Object { -not $rusByIp.ContainsKey($_) })
    $onlyRus = @($rus.Results.IP | Where-Object { -not $eurByIp.ContainsKey($_) })

    $rows = @()
    foreach ($r in $eur.Results) {
        if (-not $rusByIp.ContainsKey($r.IP)) { continue }
        $e = $r
        $u = $rusByIp[$r.IP]

        $blocked  = ($e.IsSSHOK -and (-not $u.IsSSHOK))        # SSH был в EUR, пропал в RUS
        $pingLost = ($e.IsPingOK -and (-not $u.IsPingOK))      # пинг был в EUR, пропал в RUS
        $pingSpam = ((-not $e.IsPingOK) -and $u.IsPingOK)      # пинга не было в EUR, но есть в RUS -> спам

        $noServer = (-not $e.IsPingOK) -and (-not $u.IsPingOK) -and `
                    (-not $e.IsSSHOK) -and (-not $u.IsSSHOK)

        # Итоговый веб-статус по каждой стороне
        $eWeb = Get-WebStatus -Https $e.Https -Http $e.Http
        $uWeb = Get-WebStatus -Https $u.Https -Http $u.Http

        # Веб-блокировка: в EUR веб был жив (open), в RUS стал tcp_only или closed
        $webBlocked = $false
        if ($webAvailable -and $eWeb -eq 'open' -and ($uWeb -eq 'tcp_only' -or $uWeb -eq 'closed')) {
            $webBlocked = $true
        }
        # Веб-база: хосты, где веб был доступен из EUR
        $webBase = ($webAvailable -and $eWeb -eq 'open')

        # Единый флаг "БЛОК ТСПУ" по любому из каналов
        $tspu = $pingLost -or $blocked -or $webBlocked

        $verdict =
            if ($blocked)                              { "SSH заблокирован" }
            elseif ($e.IsSSHOK -and $u.IsSSHOK)        { "доступен в обеих" }
            elseif ((-not $e.IsSSHOK) -and $u.IsSSHOK) { "SSH только в RUS" }
            elseif ($noServer)                         { "нет сервера" }
            else                                       { "SSH недоступен" }

        $row = [PSCustomObject]@{
            IP           = $e.IP
            SSH_EUR      = if ($e.IsSSHOK)  { "да ($($e.SSHPort))" } else { "нет" }
            SSH_RUS      = if ($u.IsSSHOK)  { "да ($($u.SSHPort))" } else { "нет" }
            Ping_EUR     = if ($e.IsPingOK) { "да" } else { "нет" }
            Ping_RUS     = if ($u.IsPingOK) { "да" } else { "нет" }
            Web_EUR      = if ($webAvailable) { Format-WebCell -Https $e.Https -Http $e.Http } else { "—" }
            Web_RUS      = if ($webAvailable) { Format-WebCell -Https $u.Https -Http $u.Http } else { "—" }
            'Вердикт SSH' = $verdict
            ТСПУ         = if ($tspu) { "БЛОК ТСПУ" } else { "" }
            _blocked     = $blocked
            _pingLost    = $pingLost
            _pingSpam    = $pingSpam
            _baseSSH     = $e.IsSSHOK
            _webBase     = $webBase
            _webBlocked  = $webBlocked
            _tspu        = $tspu
        }
        $rows += $row
    }

    # Время пинга по каждой стороне (только ответившие)
    $eurPing = @($eur.Results | Where-Object { $_.IsPingOK -and $null -ne $_.PingMs } | ForEach-Object { [double]$_.PingMs })
    $rusPing = @($rus.Results | Where-Object { $_.IsPingOK -and $null -ne $_.PingMs } | ForEach-Object { [double]$_.PingMs })

    [PSCustomObject]@{
        Rows         = $rows
        OnlyEur      = $onlyEur
        OnlyRus      = $onlyRus
        EurTime      = $eur.Timestamp
        RusTime      = $rus.Timestamp
        Matched      = $rows.Count
        BaseSSH      = @($rows | Where-Object { $_._baseSSH }).Count
        Blocked      = @($rows | Where-Object { $_._blocked }).Count
        PingLost     = @($rows | Where-Object { $_._pingLost }).Count
        PingSpam     = @($rows | Where-Object { $_._pingSpam }).Count
        WebAvailable = $webAvailable
        WebBase      = @($rows | Where-Object { $_._webBase }).Count
        WebBlocked   = @($rows | Where-Object { $_._webBlocked }).Count
        TspuCount    = @($rows | Where-Object { $_._tspu }).Count
        PingStatEur  = Get-PingStats -Values $eurPing
        PingStatRus  = Get-PingStats -Values $rusPing
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
    if ($cmp.WebAvailable) {
        Write-Cmp "ВЕБ ЗАБЛОКИРОВАНО в RUS         : $($cmp.WebBlocked) из $($cmp.WebBase) ($(Get-Percent $cmp.WebBlocked $cmp.WebBase)% от веб-базы)" -Color Red
    } else {
        Write-Cmp "ВЕБ (80/443)                    : не проверялся (нужен -CheckHTTP yes в обоих прогонах)" -Color Gray
    }
    Write-Cmp "Признаков БЛОК ТСПУ (любой канал): $($cmp.TspuCount)" -Color $(if ($cmp.TspuCount -gt 0) { 'Red' } else { 'Gray' })
    Write-Cmp ""
    Write-Cmp "Пинг был в EUR, нет в RUS      : $($cmp.PingLost)" -Color $(if ($cmp.PingLost -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Cmp "Пинга не было в EUR, есть в RUS: $($cmp.PingSpam)" -Color $(if ($cmp.PingSpam -gt 0) { 'Red' } else { 'Gray' })
    if ($cmp.PingSpam -gt 0) {
        Write-Cmp "  ^ подозрение на блокировку за спам" -Color Red
    }
    Write-Cmp ""
    foreach ($l in (Get-PingBlockLines -Label "Время пинга EUR" -Stat $cmp.PingStatEur)) { Write-Cmp $l }
    foreach ($l in (Get-PingBlockLines -Label "Время пинга RUS" -Stat $cmp.PingStatRus)) { Write-Cmp $l }
    Write-Cmp "========================================================="

    Write-Cmp ""
    Write-Cmp "Детализация:"
    $table = $cmp.Rows |
        Select-Object IP, SSH_EUR, SSH_RUS, Ping_EUR, Ping_RUS, Web_EUR, Web_RUS, 'Вердикт SSH', ТСПУ |
        Format-Table -AutoSize | Out-String -Width 250
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
            Подсеть   = $sub
            База      = $cmp.BaseSSH
            Заблок    = $cmp.Blocked
            'SSH %'   = "$(Get-Percent $cmp.Blocked $cmp.BaseSSH)%"
            'Веб %'   = if ($cmp.WebAvailable) { "$(Get-Percent $cmp.WebBlocked $cmp.WebBase)%" } else { "—" }
            _base     = $cmp.BaseSSH
            _blocked  = $cmp.Blocked
            _webBase  = $cmp.WebBase
            _webBlk   = $cmp.WebBlocked
            _webAvail = $cmp.WebAvailable
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
        Select-Object Подсеть, База, Заблок, 'SSH %', 'Веб %' |
        Format-Table -AutoSize | Out-String -Width 200
    Write-Cmp $table.TrimEnd()

    $totalBase    = ($summary | Measure-Object -Property _base -Sum).Sum
    $totalBlocked = ($summary | Measure-Object -Property _blocked -Sum).Sum
    Write-Cmp ""
    Write-Cmp "---------------------------------------------------------"
    Write-Cmp "ИТОГО SSH: заблокировано $totalBlocked из $totalBase ($(Get-Percent $totalBlocked $totalBase)% от общей базы)" -Color Red

    # Итог по вебу — только если хотя бы одна подсеть проверялась с вебом
    $webRows = @($summary | Where-Object { $_._webAvail })
    if ($webRows.Count -gt 0) {
        $totalWebBase = ($webRows | Measure-Object -Property _webBase -Sum).Sum
        $totalWebBlk  = ($webRows | Measure-Object -Property _webBlk  -Sum).Sum
        Write-Cmp "ИТОГО ВЕБ: заблокировано $totalWebBlk из $totalWebBase ($(Get-Percent $totalWebBlk $totalWebBase)% от веб-базы)" -Color Red
    }
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
