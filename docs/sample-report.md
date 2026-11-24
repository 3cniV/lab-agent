# Security Assessment: 172.17.0.0/24

**Method:** I ran a ping sweep of the subnet, then a top1000 TCP scan and a full 65535-port TCP scan of the one live host. I did not scan UDP. I did not attempt exploitation, authentication, or banner/configuration checks beyond what the scanner reported. The full scan found 4 ports that top1000 missed: 3632, 6697, 8787 and 43563.

## 1) Hosts found
| IP | Hostname | MAC |
|---|---|---|
| 172.17.0.2 | unknown | BA:0E:1B:8B:E8:39 |

This is the only live host. The OS is unknown, because the tool did not report one. The service banners suggest an old Debian/Ubuntu-based system, but that is an inference.

## 2) Services on 172.17.0.2 (25 open TCP ports)
| Port | Service | Product / version reported |
|---|---|---|
| 21 | FTP | vsftpd 2.3.4 |
| 22 | SSH | OpenSSH 4.7p1 Debian 8ubuntu1 |
| 23 | Telnet | Linux telnetd (version unknown) |
| 25 | SMTP | Postfix smtpd (version unknown) |
| 80 | HTTP | Apache httpd 2.2.8 |
| 111 | rpcbind | version 2 |
| 139, 445 | NetBIOS/SMB | Samba smbd 3.X–4.X (exact version unknown) |
| 512 | rexec | netkit-rsh rexecd |
| 513 | rlogin | unknown product |
| 514 | tcpwrapped (rsh/shell) | unknown |
| 1099 | Java RMI | GNU Classpath grmiregistry |
| 1524 | ingreslock | unknown |
| 2121 | FTP | ProFTPD 1.3.1 |
| 3306 | MySQL | 5.0.51a-3ubuntu5 |
| 3632 | distccd | v1 |
| 5432 | PostgreSQL | 8.3.0–8.3.7 |
| 5900 | VNC | unknown version |
| 6000 | X11 | unknown |
| 6667, 6697 | IRC | UnrealIRCd (version unknown) |
| 8009 | AJP13 | Apache Jserv |
| 8180 | HTTP | Apache Tomcat/Coyote JSP engine 1.1 |
| 8787 | Ruby DRb | unknown version |
| 43563 | Java RMI | GNU Classpath grmiregistry |

## 3) Risks ranked by severity
I did not verify any of these. Each rating is based on the exposed service and version the scanner reported. No CVE IDs are cited, because the tool output doesn't list any. Confirm exact patch levels before assigning CVEs.

**Critical (unauthenticated remote access or code execution is likely, or the service is inherently unsafe)**
- **Port 1524, ingreslock.** This port is open. Ingreslock is a legacy service, and an open listener on it is a well-known sign of a backdoor or bind shell. Whether it gives shell access is unconfirmed.
- **Port 21, vsftpd 2.3.4.** The version string is old, and this specific version is publicly known to have been distributed with a backdoor. I did not test for it.
- **Ports 512, 513, 514, rexec/rlogin/rsh.** These are legacy r-services. They send credentials in cleartext and rely on host-based trust, which is weak.
- **Port 3632, distccd.** An exposed distributed-compile daemon. It is often abusable for remote command execution when it is not restricted by access list. Its access controls are unknown.
- **Port 8787, Ruby DRb and ports 1099/43563, Java RMI.** These are remote-object services. They often permit remote code execution when exposed without authentication or a restrictive security manager. Their authentication state is unknown.
- **Port 6667/6697, UnrealIRCd.** The version was not reported, so I can't say whether it is a known-vulnerable build. Treat it as unverified and check it.

**High**
- **Port 23, Telnet.** Remote login in cleartext, so credentials can be sniffed.
- **Port 5900, VNC.** Remote desktop. The authentication method is unknown, and it may be weak or absent.
- **Port 6000, X11.** Open X server. If access control is off, an attacker could capture the screen or keystrokes. Its access control state is unknown.
- **Ports 3306 (MySQL 5.0.51a) and 5432 (PostgreSQL 8.3.x).** Databases are reachable over the network. Both are very old releases that are likely end-of-life. Authentication strength is unknown.
- **Ports 139/445, Samba.** SMB is exposed and the version is imprecise. Share, guest and signing configuration are unknown.
- **Port 2121, ProFTPD 1.3.1, and Port 80, Apache 2.2.8.** Both are old versions, likely unsupported.
- **Ports 8180 (Tomcat) and 8009 (AJP13).** The Tomcat management interface and AJP connector are exposed. Whether the manager is reachable or uses default credentials is unknown.
- **Port 22, OpenSSH 4.7p1.** An old version that is likely unsupported.

**Medium**
- **Port 111, rpcbind.** It can leak information about RPC services.
- **Port 25, Postfix.** The version is unknown. I did not test for open relay or user enumeration.

**Overall posture:** Very poor. The host exposes 25 ports, many of them legacy and cleartext services, and most of the versions reported are old. Several services, including the r-services, ingreslock, distccd, DRb and RMI, are risky by design. This resembles an intentionally vulnerable training target. It should stay isolated and should not hold real data or credentials.

## 4) Recommended defensive mitigations
1. **Reduce the attack surface.** Disable every service that isn't needed. The first to go should be ingreslock, rexec/rlogin/rsh, telnet, distccd, DRb, the X11 TCP listener, and the second FTP server.
2. **Replace cleartext protocols.** Use SSH instead of telnet and r-services, and SFTP or FTPS instead of FTP.
3. **Patch or replace outdated software.** Upgrade or retire the old versions of vsftpd, ProFTPD, OpenSSH, Apache, MySQL, PostgreSQL, Samba, Postfix and Tomcat. If the OS itself is end-of-life, rebuild on a supported release.
4. **Run a firewall with default-deny.** Allow only the ports the host's role requires. Bind databases (3306, 5432), RMI, DRb and AJP to localhost or to specific management hosts.
5. **Harden remote access.**
   - Put VNC behind an SSH tunnel or VPN, and require strong authentication.
   - Disable X11 TCP listening.
   - Restrict SSH to key-based login and disable root login.
6. **Secure the application services.**
   - Remove or restrict the Tomcat manager and AJP connector, and change any default credentials.
   - Limit database accounts to specific hosts, with strong passwords.
   - Review Samba shares to disable guest access and require SMB signing.
7. **Verify the unknowns with authenticated checks.** Confirm the OS and patch levels, the UnrealIRCd version, and the authentication state of VNC, X11, distccd, DRb and RMI. Check the ingreslock listener and the vsftpd binary for tampering. If a compromise is suspected, rebuild the host from a clean image.
8. **Add monitoring.** Log connections to these services and alert on unexpected inbound connections. Re-scan after remediation, and include UDP in a follow-up scan.