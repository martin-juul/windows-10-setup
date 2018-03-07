#Requires -RunAsAdministrator
# ==========================================
# Copyright 2018 snowydane
# Licensed under MIT for public use
# ==========================================

$basePath = "c:\temp\snowydane-setup"
If(!(Test-Path $basePath))
{
      New-Item -ItemType Directory -Force -Path $basePath
      New-Item -ItemType Directory -Force -Path $basePath'\logs'
}

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-String

# Install Applications with choco
iex ((new-object net.webClient).DownloadString('https://raw.githubusercontent.com/snowydane/windows-10-setup/master/windows10-choco-setup.ps1')) | Out-String

# Install Google Drive File Stream
iex ((new-object net.webClient).DownloadString('https://raw.githubusercontent.com/snowydane/windows-10-setup/master/google-drive-file-stream.ps1')) | Out-String
