@echo off
set NSSM_PATH="C:\Program Files (x86)\E-IMZO Client\nssm.exe"
set SERVICE_NAME=eimzo-client
%NSSM_PATH% restart %SERVICE_NAME%
pause