<#
    SUPER MENU POWERSHELL - FERRAMENTAS DIÁRIAS
    Versão: 2.1 (Correções: encoding, parsing e fechamento de blocos)
    Desenvolvido por: Arthur Severino
#>

# ==============================
# BOOTSTRAP (evita problemas de acentuação)
# ==============================
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
} catch {}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================
# UTILITÁRIOS
# ==============================
function Pause-Console {
    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-MainMenu {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "|           SUPER MENU POWERSHELL               |" -ForegroundColor Yellow
    Write-Host "|                                              |"
    Write-Host "| Desenvolvido por Arthur Severino              |"
    Write-Host "| LinkedIn: https://www.linkedin.com/in/arthur-severino-368b31232/ |"
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "| 0.  Sair                                      |"
    Write-Host "| 1.  Informações do Sistema                    |"
    Write-Host "| 2.  Gerenciamento de Usuários                 |"
    Write-Host "| 3.  Monitoramento de Processos/Serviços       |"
    Write-Host "| 4.  Ferramentas de Rede                       |"
    Write-Host "| 5.  Gerenciamento de Disco/Arquivos           |"
    Write-Host "| 6.  Tarefas Agendadas                         |"
    Write-Host "| 7.  Atualizações do Windows                   |"
    Write-Host "| 8.  Auditoria e Logs                          |"
    Write-Host "| 9.  Ferramentas de Backup                     |"
    Write-Host "| 10. Otimização do Sistema                     |"
    Write-Host "| 11. Gerenciamento de Impressoras              |"
    Write-Host "| 12. Controle de Aplicativos                   |"
    Write-Host "| 13. Ferramentas AD (Active Directory)         |"
    Write-Host "| 14. Virtualização                             |"
    Write-Host "================================================" -ForegroundColor Cyan
}

# ==============================
# 1) SISTEMA
# ==============================
function System-Info {
    Clear-Host
    Write-Host "`n=== INFORMAÇÕES COMPLETAS DO SISTEMA ===" -ForegroundColor Green

    $osInfo  = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, BuildNumber, CSName
    $cpuInfo = Get-CimInstance Win32_Processor        | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
    $memInfo = Get-CimInstance Win32_PhysicalMemory   | Measure-Object -Property Capacity -Sum |
        Select-Object @{Name="TotalGB";Expression={[math]::Round($_.Sum/1GB,2)}}

    Write-Host "`n[SO]" -ForegroundColor Yellow
    $osInfo | Format-List

    Write-Host "`n[CPU]" -ForegroundColor Yellow
    $cpuInfo | Format-List

    Write-Host "`n[MEMÓRIA]" -ForegroundColor Yellow
    $memInfo | Format-List

    Write-Host "`n[ARMAZENAMENTO]" -ForegroundColor Yellow
    Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, HealthStatus | Format-Table -AutoSize

    Write-Host "`n[BIOS]" -ForegroundColor Yellow
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version, SerialNumber | Format-List

    Pause-Console
}

# ==============================
# 2) USUÁRIOS LOCAIS
# ==============================
function User-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE USUÁRIOS (LOCAIS) ===" -ForegroundColor Green
        Write-Host "1. Listar usuários locais"
        Write-Host "2. Criar novo usuário local"
        Write-Host "3. Remover usuário local"
        Write-Host "4. Alterar senha de usuário"
        Write-Host "5. Adicionar usuário a grupo local"
        Write-Host "6. Listar grupos locais"
        Write-Host "7. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' {
                    Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize
                    Pause-Console
                }
                '2' {
                    $username    = Read-Host "Digite o nome do novo usuário"
                    $description = Read-Host "Digite a descrição do usuário"
                    $password    = Read-Host "Digite a senha" -AsSecureString
                    New-LocalUser -Name $username -Description $description -Password $password
                    Write-Host "Usuário '$username' criado com sucesso!" -ForegroundColor Green
                    Pause-Console
                }
                '3' {
                    $username = Read-Host "Digite o nome do usuário a ser removido"
                    Remove-LocalUser -Name $username
                    Write-Host "Usuário '$username' removido com sucesso!" -ForegroundColor Green
                    Pause-Console
                }
                '4' {
                    $username = Read-Host "Digite o nome do usuário"
                    $password = Read-Host "Digite a nova senha" -AsSecureString
                    Set-LocalUser -Name $username -Password $password
                    Write-Host "Senha alterada com sucesso para '$username'!" -ForegroundColor Green
                    Pause-Console
                }
                '5' {
                    $username = Read-Host "Digite o nome do usuário"
                    $group    = Read-Host "Digite o nome do grupo (ex: Administradores)"
                    Add-LocalGroupMember -Group $group -Member $username
                    Write-Host "Usuário '$username' adicionado ao grupo '$group'!" -ForegroundColor Green
                    Pause-Console
                }
                '6' {
                    Get-LocalGroup | Select-Object Name, Description | Format-Table -AutoSize
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '7')
}

# ==============================
# 3) PROCESSOS/SERVIÇOS
# ==============================
function Process-Services {
    do {
        Clear-Host
        Write-Host "`n=== PROCESSOS E SERVIÇOS ===" -ForegroundColor Green
        Write-Host "1. Listar processos (top 10 por CPU)"
        Write-Host "2. Listar processos (top 10 por Memória)"
        Write-Host "3. Encerrar processo (por Nome ou ID)"
        Write-Host "4. Listar serviços em execução"
        Write-Host "5. Listar todos os serviços"
        Write-Host "6. Iniciar/Parar serviço"
        Write-Host "7. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' { Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table -AutoSize; Pause-Console }
                '2' { Get-Process | Sort-Object WS  -Descending | Select-Object -First 10 | Format-Table -AutoSize; Pause-Console }
                '3' {
                    $process = Read-Host "Digite o Nome ou ID do processo"
                    if ($process -match '^\d+$') { Stop-Process -Id   ([int]$process) -Force }
                    else                          { Stop-Process -Name $process        -Force }
                    Write-Host "Processo '$process' encerrado!" -ForegroundColor Green
                    Pause-Console
                }
                '4' { Get-Service | Where-Object Status -eq 'Running' | Select-Object DisplayName, Status, StartType | Format-Table -AutoSize; Pause-Console }
                '5' { Get-Service | Select-Object DisplayName, Status, StartType | Format-Table -AutoSize; Pause-Console }
                '6' {
                    $service = Read-Host "Digite o nome do serviço (Name)"
                    $action  = Read-Host "Deseja (1) Iniciar ou (2) Parar?"
                    if ($action -eq '1') { Start-Service -Name $service; Write-Host "Serviço '$service' iniciado!" -ForegroundColor Green }
                    elseif ($action -eq '2') { Stop-Service -Name $service; Write-Host "Serviço '$service' parado!" -ForegroundColor Green }
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '7')
}

# ==============================
# 4) REDE
# ==============================
function Network-Tools {
    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE REDE ===" -ForegroundColor Green
        Write-Host "1. Configuração de rede"
        Write-Host "2. Testar conectividade (ICMP/DNS)"
        Write-Host "3. Testar porta específica"
        Write-Host "4. Analisar conexões ativas"
        Write-Host "5. Liberar/renew DHCP"
        Write-Host "6. Flush DNS"
        Write-Host "7. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' { Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-Table -AutoSize; Pause-Console }
                '2' { $hostname = Read-Host "Digite o host (ex: google.com)"; Test-NetConnection -ComputerName $hostname -InformationLevel Detailed; Pause-Console }
                '3' { $hostname = Read-Host "Digite o host/IP"; $port = Read-Host "Digite a porta"; Test-NetConnection -ComputerName $hostname -Port ([int]$port); Pause-Console }
                '4' {
                    Get-NetTCPConnection | Where-Object State -eq 'Established' |
                        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                        Format-Table -AutoSize
                    Pause-Console
                }
                '5' { ipconfig /release | Out-Null; ipconfig /renew | Out-Null; Write-Host "Endereço IP renovado!" -ForegroundColor Green; Pause-Console }
                '6' { ipconfig /flushdns | Out-Null; Write-Host "Cache DNS limpo!" -ForegroundColor Green; Pause-Console }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '7')
}

# ==============================
# 5) DISCO/ARQUIVOS
# ==============================
function Disk-File-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE DISCO/ARQUIVOS ===" -ForegroundColor Green
        Write-Host "1. Espaço em disco"
        Write-Host "2. Listar arquivos grandes"
        Write-Host "3. Limpar arquivos temporários"
        Write-Host "4. Procurar arquivos"
        Write-Host "5. Verificar integridade do disco (chkdsk /f)"
        Write-Host "6. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' {
                    Get-Volume | Select-Object DriveLetter, FileSystemLabel, SizeRemaining, Size |
                        ForEach-Object {
                            $used = $_.Size - $_.SizeRemaining
                            $percentUsed = if ($_.Size -gt 0) { ($used / $_.Size) * 100 } else { 0 }
                            [PSCustomObject]@{
                                Unidade    = $_.DriveLetter
                                Rotulo     = $_.FileSystemLabel
                                "Total (GB)" = [math]::Round($_.Size/1GB, 2)
                                "Usado (GB)" = [math]::Round($used/1GB, 2)
                                "Livre (GB)" = [math]::Round($_.SizeRemaining/1GB, 2)
                                "% Usado"    = [math]::Round($percentUsed, 2)
                            }
                        } | Format-Table -AutoSize
                    Pause-Console
                }
                '2' {
                    $path = Read-Host "Digite o caminho (ex: C:\)"
                    $size = Read-Host "Tamanho mínimo em MB (ex: 100)"
                    Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt ([int]$size * 1MB) } |
                        Sort-Object Length -Descending |
                        Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}} |
                        Format-Table -AutoSize
                    Pause-Console
                }
                '3' {
                    $tempFolders = @("$env:TEMP", "$env:WINDIR\Temp", "$env:USERPROFILE\AppData\Local\Temp")
                    $totalFreed = 0.0

                    foreach ($folder in $tempFolders) {
                        if (Test-Path $folder) {
                            $files = Get-ChildItem $folder -Recurse -Force -ErrorAction SilentlyContinue
                            $sizeMb = [double](($files | Measure-Object -Property Length -Sum).Sum / 1MB)
                            $totalFreed += $sizeMb

                            $files | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                            Write-Host ("Limpos {0} MB de {1}" -f ([math]::Round($sizeMb, 2)), $folder)
                        }
                    }

                    Write-Host ("`nTotal liberado: {0} MB" -f ([math]::Round($totalFreed, 2))) -ForegroundColor Green
                    Pause-Console
                }
                '4' {
                    $path   = Read-Host "Digite o caminho (ex: C:\)"
                    $filter = Read-Host "Digite o filtro (ex: *.log ou relatorio*)"
                    Get-ChildItem -Path $path -Filter $filter -Recurse -ErrorAction SilentlyContinue |
                        Select-Object FullName, LastWriteTime, Length |
                        Format-Table -AutoSize
                    Pause-Console
                }
                '5' {
                    Write-Host "O CHKDSK pode exigir reinício dependendo do disco." -ForegroundColor Yellow
                    chkdsk /f
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '6')
}

# ==============================
# 6) TAREFAS AGENDADAS
# ==============================
function Scheduled-Tasks {
    Clear-Host
    Write-Host "`n=== TAREFAS AGENDADAS ===" -ForegroundColor Green
    Get-ScheduledTask | Select-Object TaskName, State, Author | Format-Table -AutoSize
    Pause-Console
}

# ==============================
# 7) WINDOWS UPDATES
# ==============================
function Windows-Updates {
    Clear-Host
    Write-Host "`n=== ATUALIZAÇÕES DO WINDOWS ===" -ForegroundColor Green

    try {
        if (-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
            Write-Host "Módulo PSWindowsUpdate não encontrado. Tentando instalar..." -ForegroundColor Yellow
            Install-Module PSWindowsUpdate -Force -Confirm:$false -Scope CurrentUser
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
    } catch {
        Write-Host "Não foi possível instalar/importar o PSWindowsUpdate: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Execute o PowerShell como Administrador e/ou ajuste TLS/Proxy se necessário." -ForegroundColor Yellow
        Pause-Console
        return
    }

    Write-Host "1. Verificar atualizações disponíveis"
    Write-Host "2. Instalar atualizações"
    Write-Host "3. Histórico de atualizações"
    Write-Host "4. Voltar"

    $choice = Read-Host "`nSelecione uma opção"

    try {
        switch ($choice) {
            '1' { Get-WindowsUpdate -Verbose; Pause-Console }
            '2' { Install-WindowsUpdate -AcceptAll -AutoReboot; Pause-Console }
            '3' { Get-WUHistory | Select-Object Date, Title, Result | Format-Table -AutoSize; Pause-Console }
        }
    } catch {
        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
        Pause-Console
    }
}

# ==============================
# 8) AUDITORIA / LOGS
# ==============================
function Audit-Logs {
    do {
        Clear-Host
        Write-Host "`n=== AUDITORIA E LOGS ===" -ForegroundColor Green
        Write-Host "1. Visualizar logs de sistema"
        Write-Host "2. Visualizar logs de aplicação"
        Write-Host "3. Visualizar logs de segurança"
        Write-Host "4. Procurar por termo nos logs"
        Write-Host "5. Limpar logs (System/Application/Security)"
        Write-Host "6. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' { Get-EventLog -LogName System      -Newest 20 | Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize; Pause-Console }
                '2' { Get-EventLog -LogName Application -Newest 20 | Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize; Pause-Console }
                '3' { Get-EventLog -LogName Security    -Newest 20 | Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize; Pause-Console }
                '4' {
                    $logName    = Read-Host "Digite o nome do log (System, Application, Security)"
                    $searchTerm = Read-Host "Digite o termo para pesquisar"

                    Get-EventLog -LogName $logName -Newest 1000 |
                        Where-Object { $_.Message -like "*$searchTerm*" } |
                        Select-Object TimeGenerated, Source, Message |
                        Format-Table -Wrap -AutoSize
                    Pause-Console
                }
                '5' {
                    Clear-EventLog -LogName System, Application, Security
                    Write-Host "Logs limpos com sucesso!" -ForegroundColor Green
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '6')
}

# ==============================
# 9) BACKUP
# ==============================
function Backup-Tools {
    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE BACKUP ===" -ForegroundColor Green
        Write-Host "1. Criar backup de arquivos (zip)"
        Write-Host "2. Restaurar backup (zip)"
        Write-Host "3. Verificar backups existentes (zip)"
        Write-Host "4. Fazer backup de drivers"
        Write-Host "5. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' {
                    $source      = Read-Host "Digite o caminho de origem (ex: C:\Pasta)"
                    $destination = Read-Host "Digite o caminho de destino (ex: D:\Backup)"
                    $backupName  = "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"

                    if (-not (Test-Path $destination)) { New-Item -ItemType Directory -Path $destination -Force | Out-Null }

                    Compress-Archive -Path $source -DestinationPath (Join-Path $destination $backupName) -CompressionLevel Optimal -Force
                    Write-Host "Backup criado em $(Join-Path $destination $backupName)" -ForegroundColor Green
                    Pause-Console
                }
                '2' {
                    $backupFile  = Read-Host "Digite o caminho do arquivo de backup (ex: D:\Backup\arquivo.zip)"
                    $destination = Read-Host "Digite o caminho para restauração (ex: C:\Restore)"

                    if (-not (Test-Path $destination)) { New-Item -ItemType Directory -Path $destination -Force | Out-Null }

                    Expand-Archive -Path $backupFile -DestinationPath $destination -Force
                    Write-Host "Backup restaurado para $destination" -ForegroundColor Green
                    Pause-Console
                }
                '3' {
                    $backupDir = Read-Host "Digite o caminho dos backups (ex: D:\Backup)"
                    Get-ChildItem -Path $backupDir -Filter *.zip -ErrorAction SilentlyContinue |
                        Select-Object Name, LastWriteTime, Length |
                        Format-Table -AutoSize
                    Pause-Console
                }
                '4' {
                    $destination = Read-Host "Digite o caminho para salvar (ex: D:\Backup\Drivers)"

                    if (-not (Test-Path $destination)) { New-Item -ItemType Directory -Path $destination -Force | Out-Null }

                    $backupFile = Join-Path $destination ("DriversBackup_{0}.txt" -f (Get-Date -Format 'yyyyMMdd'))

                    Write-Host "`nColetando informações de drivers..."
                    Get-WindowsDriver -Online -All | Out-File -FilePath $backupFile -Encoding utf8

                    Write-Host "Exportando drivers..."
                    Export-WindowsDriver -Online -Destination $destination

                    Write-Host "`nBackup dos drivers concluído com sucesso!" -ForegroundColor Green
                    Write-Host "Local: $destination" -ForegroundColor Yellow
                    Write-Host "Arquivo de informações: $backupFile" -ForegroundColor Yellow
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '5')
}

# ==============================
# 10) OTIMIZAÇÃO
# ==============================
function System-Optimization {
    do {
        Clear-Host
        Write-Host "`n=== OTIMIZAÇÃO DO SISTEMA ===" -ForegroundColor Green
        Write-Host "1. Desfragmentar disco (C:)"
        Write-Host "2. Limpar disco (cleanmgr /sagerun:1)"
        Write-Host "3. Otimizar unidades (Fixed)"
        Write-Host "4. Ver programas de inicialização"
        Write-Host "5. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' { Optimize-Volume -DriveLetter C -Defrag -Verbose; Write-Host "Desfragmentação concluída!" -ForegroundColor Green; Pause-Console }
                '2' { cleanmgr /sagerun:1 | Out-Null; Write-Host "Limpeza de disco executada!" -ForegroundColor Green; Pause-Console }
                '3' { Get-Volume | Where-Object DriveType -eq 'Fixed' | Optimize-Volume -Verbose; Write-Host "Otimização concluída!" -ForegroundColor Green; Pause-Console }
                '4' {
                    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '5')
}

# ==============================
# 11) IMPRESSORAS
# ==============================
function Printer-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE IMPRESSORAS ===" -ForegroundColor Green
        Write-Host "1. Listar impressoras instaladas"
        Write-Host "2. Adicionar impressora"
        Write-Host "3. Remover impressora"
        Write-Host "4. Limpar fila de impressão"
        Write-Host "5. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' { Get-Printer | Select-Object Name, Type, PortName, Shared, Published | Format-Table -AutoSize; Pause-Console }
                '2' {
                    $printerName = Read-Host "Digite o nome da impressora"
                    $driverName  = Read-Host "Digite o nome do driver"
                    $portName    = Read-Host "Digite a porta (ex: IP_192.168.1.100)"
                    $ipAddress   = Read-Host "Digite o endereço IP da impressora"

                    Add-PrinterPort -Name $portName -PrinterHostAddress $ipAddress
                    Add-Printer -Name $printerName -DriverName $driverName -PortName $portName
                    Write-Host "Impressora '$printerName' adicionada com sucesso!" -ForegroundColor Green
                    Pause-Console
                }
                '3' {
                    $printerName = Read-Host "Digite o nome da impressora para remover"
                    Remove-Printer -Name $printerName
                    Write-Host "Impressora '$printerName' removida com sucesso!" -ForegroundColor Green
                    Pause-Console
                }
                '4' {
                    Get-Printer | Where-Object JobCount -gt 0 | ForEach-Object {
                        Write-Host "Limpando fila da impressora $($_.Name)..."
                        Remove-PrintJob -PrinterName $_.Name -ID *
                    }
                    Write-Host "Filas de impressão limpas!" -ForegroundColor Green
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '5')
}

# ==============================
# 12) APPS
# ==============================
function App-Control {
    do {
        Clear-Host
        Write-Host "`n=== CONTROLE DE APLICATIVOS ===" -ForegroundColor Green
        Write-Host "1. Listar aplicativos instalados"
        Write-Host "2. Desinstalar aplicativo (registry uninstall)"
        Write-Host "3. Executar aplicativo como administrador"
        Write-Host "4. Ver apps com janela aberta"
        Write-Host "5. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' {
                    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                        Where-Object DisplayName |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                        Sort-Object DisplayName |
                        Format-Table -AutoSize
                    Pause-Console
                }
                '2' {
                    $appName = Read-Host "Digite parte do nome do aplicativo"
                    $apps = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like "*$appName*" } |
                        Select-Object DisplayName, UninstallString

                    if ($apps) {
                        $apps | Format-Table -AutoSize
                        $uninstall = Read-Host "Deseja desinstalar algum? (S/N)"
                        if ($uninstall -match '^(S|s)$') {
                            $appToRemove = Read-Host "Digite o nome exato do aplicativo"
                            $uninstallString = ($apps | Where-Object { $_.DisplayName -eq $appToRemove } | Select-Object -First 1).UninstallString
                            if ($uninstallString) {
                                Start-Process "cmd.exe" -ArgumentList "/c $uninstallString /quiet" -Wait
                                Write-Host "Aplicativo '$appToRemove' desinstalado!" -ForegroundColor Green
                            } else {
                                Write-Host "Não foi possível localizar o UninstallString do app informado." -ForegroundColor Yellow
                            }
                        }
                    } else {
                        Write-Host "Nenhum aplicativo encontrado!" -ForegroundColor Red
                    }
                    Pause-Console
                }
                '3' {
                    $appPath = Read-Host "Digite o caminho completo do aplicativo (ex: C:\app\app.exe)"
                    Start-Process -FilePath $appPath -Verb RunAs
                    Pause-Console
                }
                '4' {
                    Get-Process | Where-Object MainWindowTitle | Select-Object Name, MainWindowTitle | Format-Table -AutoSize
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '5')
}

# ==============================
# 13) ACTIVE DIRECTORY (completo no que você enviou)
# ==============================
function Show-ADUserResults {
    param([Parameter(Mandatory=$true)] $users)

    if ($users -and ($users | Measure-Object).Count -gt 0) {
        $users |
            Select-Object Name, SamAccountName, UserPrincipalName, Enabled, LastLogonDate, EmailAddress, Department, Title |
            Sort-Object Name |
            Format-Table -AutoSize

        $count = ($users | Measure-Object).Count
        Write-Host "`nTotal encontrado: $count" -ForegroundColor Yellow

        $export = Read-Host "Deseja exportar para CSV? (S/N)"
        if ($export -match '^(S|s)$') {
            $csvPath = "$env:USERPROFILE\Desktop\ADUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $users | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Dados exportados para $csvPath" -ForegroundColor Green
        }
    } else {
        Write-Host "Nenhum resultado encontrado." -ForegroundColor Yellow
    }
}

function New-ADUserWizard {
    Clear-Host
    Write-Host "`n=== ASSISTENTE DE CRIAÇÃO DE USUÁRIO (AD) ===" -ForegroundColor Cyan

    $firstName  = Read-Host "Nome"
    $lastName   = Read-Host "Sobrenome"
    $samAccount = Read-Host "Login (SamAccountName)"
    $password   = Read-Host "Senha" -AsSecureString
    $ou         = Read-Host "OU (ex: OU=Usuarios,DC=dominio,DC=com)"
    $email      = Read-Host "Email"
    $department = Read-Host "Departamento"
    $title      = Read-Host "Cargo"
    $company    = Read-Host "Empresa"

    $domain = (Get-ADDomain).DNSRoot

    $userParams = @{
        GivenName             = $firstName
        Surname               = $lastName
        Name                  = "$firstName $lastName"
        SamAccountName        = $samAccount
        UserPrincipalName     = "$samAccount@$domain"
        AccountPassword       = $password
        Path                  = $ou
        Enabled               = $true
        EmailAddress          = $email
        Department            = $department
        Title                 = $title
        Company               = $company
        ChangePasswordAtLogon = $true
    }

    try {
        New-ADUser @userParams
        Write-Host "Usuário '$samAccount' criado com sucesso!" -ForegroundColor Green

        $addGroups = Read-Host "Deseja adicionar a grupos padrão? (S/N)"
        if ($addGroups -match '^(S|s)$') {
            $defaultGroups = @("Domain Users","Staff") # ajuste conforme sua necessidade
            foreach ($g in $defaultGroups) {
                try { Add-ADGroupMember -Identity $g -Members $samAccount -ErrorAction Stop } catch {}
            }
            Write-Host "Usuário adicionado aos grupos padrão (quando aplicável)." -ForegroundColor Green
        }
    } catch {
        Write-Host "Erro ao criar usuário: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function AD-Tools {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "Módulo ActiveDirectory não está disponível neste host." -ForegroundColor Red
        Write-Host "Instale RSAT (AD DS and AD LDS Tools) para habilitar." -ForegroundColor Yellow
        Pause-Console
        return
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Host "Falha ao carregar módulo ActiveDirectory: $($_.Exception.Message)" -ForegroundColor Red
        Pause-Console
        return
    }

    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS AVANÇADAS ACTIVE DIRECTORY ===" -ForegroundColor Cyan
        Write-Host "| 1.  Busca de Usuários                       |"
        Write-Host "| 2.  Gerenciamento de Contas                 |"
        Write-Host "| 3.  Gerenciamento de Grupos                 |"
        Write-Host "| 9.  Voltar ao Menu Principal                |"
        Write-Host "================================================" -ForegroundColor Cyan

        $mainChoice = Read-Host "`nSelecione uma categoria"

        switch ($mainChoice) {
            '1' {
                do {
                    Clear-Host
                    Write-Host "`n=== BUSCA DE USUÁRIOS ===" -ForegroundColor Green
                    Write-Host "1. Buscar usuário por nome/login"
                    Write-Host "2. Buscar usuários inativos"
                    Write-Host "3. Buscar usuários desabilitados"
                    Write-Host "4. Buscar por departamento"
                    Write-Host "5. Buscar usuários com senha expirada"
                    Write-Host "6. Buscar usuários que nunca logaram"
                    Write-Host "7. Voltar"

                    $searchChoice = Read-Host "`nSelecione uma opção"

                    try {
                        switch ($searchChoice) {
                            '1' {
                                $searchTerm = Read-Host "Digite nome, sobrenome ou login"
                                $filter = "(|(Name=*$searchTerm*)(SamAccountName=*$searchTerm*)(GivenName=*$searchTerm*)(Surname=*$searchTerm*)(UserPrincipalName=*$searchTerm*)(DisplayName=*$searchTerm*))"
                                $users = Get-ADUser -LDAPFilter $filter -Properties *
                                Show-ADUserResults $users
                                Pause-Console
                            }
                            '2' {
                                $days = Read-Host "Número de dias para considerar inativo (padrão 90)"
                                if (-not $days) { $days = 90 }
                                $date = (Get-Date).AddDays(-[int]$days)
                                $users = Get-ADUser -Filter { LastLogonDate -lt $date -and Enabled -eq $true } -Properties LastLogonDate,Enabled
                                Show-ADUserResults $users
                                Pause-Console
                            }
                            '3' {
                                $users = Get-ADUser -Filter { Enabled -eq $false } -Properties Enabled
                                Show-ADUserResults $users
                                Pause-Console
                            }
                            '4' {
                                $dept = Read-Host "Digite o departamento"
                                $users = Get-ADUser -Filter "Department -like '*$dept*'" -Properties Department
                                Show-ADUserResults $users
                                Pause-Console
                            }
                            '5' {
                                $users = Search-ADAccount -PasswordExpired | Where-Object ObjectClass -eq 'user'
                                Show-ADUserResults $users
                                Pause-Console
                            }
                            '6' {
                                $users = Get-ADUser -Filter * -Properties LastLogonDate | Where-Object { -not $_.LastLogonDate }
                                Show-ADUserResults $users
                                Pause-Console
                            }
                        }
                    } catch {
                        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
                        Pause-Console
                    }
                } while ($searchChoice -ne '7')
            }

            '2' {
                do {
                    Clear-Host
                    Write-Host "`n=== GERENCIAMENTO DE CONTAS ===" -ForegroundColor Green
                    Write-Host "1. Criar novo usuário"
                    Write-Host "2. Desbloquear conta"
                    Write-Host "3. Resetar senha"
                    Write-Host "4. Habilitar/Desabilitar conta"
                    Write-Host "5. Mover usuário para outra OU"
                    Write-Host "6. Adicionar aos grupos do usuário"
                    Write-Host "7. Remover dos grupos do usuário"
                    Write-Host "8. Configurar propriedades da conta"
                    Write-Host "9. Voltar"

                    $accountChoice = Read-Host "`nSelecione uma opção"

                    try {
                        switch ($accountChoice) {
                            '1' { New-ADUserWizard; Pause-Console }
                            '2' {
                                $username = Read-Host "Digite o login do usuário"
                                Unlock-ADAccount -Identity $username
                                Write-Host "Conta '$username' desbloqueada com sucesso!" -ForegroundColor Green
                                Get-ADUser -Identity $username -Properties LockedOut | Select-Object Name, SamAccountName, LockedOut | Format-Table -AutoSize
                                Pause-Console
                            }
                            '3' {
                                $username = Read-Host "Digite o login do usuário"
                                $newPass  = Read-Host "Digite a nova senha" -AsSecureString
                                Set-ADAccountPassword -Identity $username -NewPassword $newPass -Reset
                                Write-Host "Senha alterada com sucesso!" -ForegroundColor Green

                                $changePass = Read-Host "Forçar mudança de senha no próximo login? (S/N)"
                                if ($changePass -match '^(S|s)$') {
                                    Set-ADUser -Identity $username -ChangePasswordAtLogon $true
                                    Write-Host "Usuário deverá alterar a senha no próximo login." -ForegroundColor Yellow
                                }

                                $unlock = Read-Host "Deseja desbloquear a conta também? (S/N)"
                                if ($unlock -match '^(S|s)$') {
                                    Unlock-ADAccount -Identity $username
                                    Write-Host "Conta desbloqueada!" -ForegroundColor Green
                                }
                                Pause-Console
                            }
                            '4' {
                                $username = Read-Host "Digite o login do usuário"
                                $user = Get-ADUser -Identity $username -Properties Enabled
                                $newStatus = -not $user.Enabled
                                Set-ADUser -Identity $username -Enabled $newStatus
                                Write-Host ("Status da conta alterado para: {0}" -f (if ($newStatus) { 'Habilitada' } else { 'Desabilitada' })) -ForegroundColor Green
                                Pause-Console
                            }
                            '5' {
                                $username = Read-Host "Digite o login do usuário"
                                $userDN = (Get-ADUser -Identity $username).DistinguishedName
                                Write-Host "DN atual: $userDN"
                                $newOU = Read-Host "Digite a OU de destino (ex: OU=Usuarios,DC=dominio,DC=com)"
                                Move-ADObject -Identity $userDN -TargetPath $newOU
                                Write-Host "Usuário movido com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '6' {
                                $username = Read-Host "Digite o login do usuário"
                                $currentGroups = Get-ADPrincipalGroupMembership -Identity $username | Select-Object Name | Sort-Object Name
                                Write-Host "`nGrupos atuais do usuário:"
                                $currentGroups | Format-Table -AutoSize

                                $groupName = Read-Host "`nDigite o nome do grupo para adicionar"
                                Add-ADGroupMember -Identity $groupName -Members $username
                                Write-Host "Usuário adicionado ao grupo '$groupName' com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '7' {
                                $username = Read-Host "Digite o login do usuário"
                                $currentGroups = Get-ADPrincipalGroupMembership -Identity $username | Select-Object Name | Sort-Object Name
                                Write-Host "`nGrupos atuais do usuário:"
                                $currentGroups | Format-Table -AutoSize

                                $groupName = Read-Host "`nDigite o nome do grupo para remover"
                                Remove-ADGroupMember -Identity $groupName -Members $username -Confirm:$false
                                Write-Host "Usuário removido do grupo '$groupName' com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '8' {
                                $username = Read-Host "Digite o login do usuário"
                                $user = Get-ADUser -Identity $username -Properties *

                                Write-Host "`nEditando propriedades de $($user.Name)"
                                $newDesc  = Read-Host ("Descrição [atual: {0}]" -f $user.Description)
                                $newOffice= Read-Host ("Escritório [atual: {0}]" -f $user.Office)
                                $newDept  = Read-Host ("Departamento [atual: {0}]" -f $user.Department)
                                $newTitle = Read-Host ("Cargo [atual: {0}]" -f $user.Title)
                                $newEmail = Read-Host ("Email [atual: {0}]" -f $user.EmailAddress)

                                $params = @{}
                                if ($newDesc)   { $params.Description  = $newDesc }
                                if ($newOffice) { $params.Office       = $newOffice }
                                if ($newDept)   { $params.Department   = $newDept }
                                if ($newTitle)  { $params.Title        = $newTitle }
                                if ($newEmail)  { $params.EmailAddress = $newEmail }

                                if ($params.Count -gt 0) {
                                    Set-ADUser -Identity $username @params
                                    Write-Host "Propriedades atualizadas com sucesso!" -ForegroundColor Green
                                } else {
                                    Write-Host "Nenhuma alteração informada." -ForegroundColor Yellow
                                }
                                Pause-Console
                            }
                        }
                    } catch {
                        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
                        Pause-Console
                    }
                } while ($accountChoice -ne '9')
            }

            '3' {
                do {
                    Clear-Host
                    Write-Host "`n=== GERENCIAMENTO DE GRUPOS ===" -ForegroundColor Green
                    Write-Host "1. Listar todos os grupos"
                    Write-Host "2. Criar novo grupo"
                    Write-Host "3. Remover grupo"
                    Write-Host "4. Listar membros de um grupo"
                    Write-Host "5. Adicionar membros a um grupo"
                    Write-Host "6. Remover membros de um grupo"
                    Write-Host "7. Configurar propriedades do grupo"
                    Write-Host "8. Voltar"

                    $groupChoice = Read-Host "`nSelecione uma opção"

                    try {
                        switch ($groupChoice) {
                            '1' {
                                Get-ADGroup -Filter * -Properties * |
                                    Select-Object Name, GroupScope, GroupCategory, Description |
                                    Sort-Object Name |
                                    Format-Table -AutoSize
                                Pause-Console
                            }
                            '2' {
                                $groupName     = Read-Host "Digite o nome do novo grupo"
                                $groupScope    = Read-Host "Escopo (Global/Universal/DomainLocal)"
                                $groupCategory = Read-Host "Categoria (Security/Distribution)"
                                $description   = Read-Host "Descrição"

                                New-ADGroup -Name $groupName -GroupScope $groupScope -GroupCategory $groupCategory -Description $description
                                Write-Host "Grupo '$groupName' criado com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '3' {
                                $groupName = Read-Host "Digite o nome do grupo para remover"
                                Remove-ADGroup -Identity $groupName -Confirm:$false
                                Write-Host "Grupo '$groupName' removido com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '4' {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $members = Get-ADGroupMember -Identity $groupName |
                                    Select-Object Name, SamAccountName, ObjectClass |
                                    Sort-Object Name

                                Write-Host "`nMembros do grupo $groupName"
                                $members | Format-Table -AutoSize

                                $export = Read-Host "Deseja exportar para CSV? (S/N)"
                                if ($export -match '^(S|s)$') {
                                    $csvPath = "$env:USERPROFILE\Desktop\$($groupName)_Members_$(Get-Date -Format 'yyyyMMdd').csv"
                                    $members | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                                    Write-Host "Lista exportada para $csvPath" -ForegroundColor Green
                                }
                                Pause-Console
                            }
                            '5' {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $membersToAdd = Read-Host "Digite os logins a adicionar (separados por vírgula)"
                                $membersArray = $membersToAdd -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                                Add-ADGroupMember -Identity $groupName -Members $membersArray
                                Write-Host "Usuários adicionados ao grupo '$groupName' com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '6' {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $membersToRemove = Read-Host "Digite os logins a remover (separados por vírgula)"
                                $membersArray = $membersToRemove -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                                Remove-ADGroupMember -Identity $groupName -Members $membersArray -Confirm:$false
                                Write-Host "Usuários removidos do grupo '$groupName' com sucesso!" -ForegroundColor Green
                                Pause-Console
                            }
                            '7' {
                                $groupName  = Read-Host "Digite o nome do grupo"
                                $managedBy  = Read-Host "Digite o login do responsável (ManagedBy)"
                                $description= Read-Host "Digite a nova descrição"
                                Set-ADGroup -Identity $groupName -ManagedBy $managedBy -Description $description
                                Write-Host "Propriedades do grupo '$groupName' atualizadas!" -ForegroundColor Green
                                Pause-Console
                            }
                        }
                    } catch {
                        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
                        Pause-Console
                    }
                } while ($groupChoice -ne '8')
            }

            '9' { return }
            default { Write-Host "Opção inválida" -ForegroundColor Red; Pause-Console }
        }
    } while ($mainChoice -ne '9')
}

# ==============================
# 14) VIRTUALIZAÇÃO (HYPER-V)
# ==============================
function Virtualization-Tools {
    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE VIRTUALIZAÇÃO ===" -ForegroundColor Green
        Write-Host "1. Listar máquinas virtuais Hyper-V"
        Write-Host "2. Iniciar VM"
        Write-Host "3. Parar VM"
        Write-Host "4. Ver status de VMs"
        Write-Host "5. Voltar"

        $choice = Read-Host "`nSelecione uma opção"

        try {
            switch ($choice) {
                '1' {
                    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
                        Get-VM | Select-Object Name, State, CPUUsage, MemoryAssigned | Format-Table -AutoSize
                    } else {
                        Write-Host "Módulo Hyper-V não disponível neste host." -ForegroundColor Red
                    }
                    Pause-Console
                }
                '2' {
                    if (-not (Get-Command Start-VM -ErrorAction SilentlyContinue)) { throw "Hyper-V não disponível." }
                    $vmName = Read-Host "Digite o nome da VM para iniciar"
                    Start-VM -Name $vmName
                    Write-Host "VM '$vmName' iniciada!" -ForegroundColor Green
                    Pause-Console
                }
                '3' {
                    if (-not (Get-Command Stop-VM -ErrorAction SilentlyContinue)) { throw "Hyper-V não disponível." }
                    $vmName = Read-Host "Digite o nome da VM para parar"
                    Stop-VM -Name $vmName -Force
                    Write-Host "VM '$vmName' parada!" -ForegroundColor Green
                    Pause-Console
                }
                '4' {
                    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
                        Get-VM | Select-Object Name, State, Status, Uptime | Format-Table -AutoSize
                    } else {
                        Write-Host "Módulo Hyper-V não disponível neste host." -ForegroundColor Red
                    }
                    Pause-Console
                }
            }
        } catch {
            Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
            Pause-Console
        }
    } while ($choice -ne '5')
}

# ==============================
# MAIN LOOP (fechado corretamente)
# ==============================
do {
    Show-MainMenu
    $selection = Read-Host "`nSelecione uma opção"

    try {
        switch ($selection) {
            '0'  { break }
            '1'  { System-Info }
            '2'  { User-Management }
            '3'  { Process-Services }
            '4'  { Network-Tools }
            '5'  { Disk-File-Management }
            '6'  { Scheduled-Tasks }
            '7'  { Windows-Updates }
            '8'  { Audit-Logs }
            '9'  { Backup-Tools }
            '10' { System-Optimization }
            '11' { Printer-Management }
            '12' { App-Control }
            '13' { AD-Tools }
            '14' { Virtualization-Tools }
            default { Write-Host "Opção inválida" -ForegroundColor Red; Pause-Console }
        }
    } catch {
        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
        Pause-Console
    }

} while ($true)

