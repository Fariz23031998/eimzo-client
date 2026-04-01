@echo off
set NSSM_PATH="C:\Program Files (x86)\E-IMZO Client\nssm.exe"
set SERVICE_NAME=eimzo-client
set APP_PATH="C:\Program Files (x86)\E-IMZO Client\eimzo-client.exe"
%NSSM_PATH% install %SERVICE_NAME% %APP_PATH%
%NSSM_PATH% start %SERVICE_NAME%
