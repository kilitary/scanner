
# build moc files
MOC=/usr/bin/moc
all: usage _CertMgr _PSClient _SCP _SExec _SFTP _SSHClient _SSHDaemon _SShell _SSHReverseTunnel _SSHTunnel 
	echo done!


usage:
	@echo "================================================================================"
	@echo "Generating metaobject information for all headers."
	@echo "Using MOC=$(MOC)"
	@echo "================================================================================"
	@echo

_CertMgr:
	$(MOC) certmgr.h -o certmgr_moc.cpp
  
_PSClient:
	$(MOC) psclient.h -o psclient_moc.cpp
  
_SCP:
	$(MOC) scp.h -o scp_moc.cpp
  
_SExec:
	$(MOC) sexec.h -o sexec_moc.cpp
  
_SFTP:
	$(MOC) sftp.h -o sftp_moc.cpp
  
_SSHClient:
	$(MOC) sshclient.h -o sshclient_moc.cpp
  
_SSHDaemon:
	$(MOC) sshdaemon.h -o sshdaemon_moc.cpp
  
_SShell:
	$(MOC) sshell.h -o sshell_moc.cpp
  
_SSHReverseTunnel:
	$(MOC) sshreversetunnel.h -o sshreversetunnel_moc.cpp
  
_SSHTunnel:
	$(MOC) sshtunnel.h -o sshtunnel_moc.cpp
  


