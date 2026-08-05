# Hozfix

Host: `cliente-wp-07`

10 fixes. Orden: acceso SSH -> datos/servicios -> perímetro (UFW/fail2ban) -> updates/reboot.

## Resumen

1. [CRITICAL] HOZ-SSH-BUNDLE - Endurecer SSH (drop-in)
2. [CRITICAL] HOZ-WEB-001 - .env legible en docroot
3. [HIGH] HOZ-WEB-101 - wp-config.php con permisos flojos
4. [HIGH] HOZ-NET-004+HOZ-DB-002 - Sacar MySQL/MariaDB de internet (bind + ufw)
5. [MEDIUM] HOZ-DOCK-010 - Publish en 0.0.0.0
6. [MEDIUM] HOZ-NET-011 - Servicio en 8080 expuesto públicamente
7. [HIGH] HOZ-USR-004 - NOPASSWD en sudoers
8. [HIGH] HOZ-FW-001 - UFW inactivo
9. [MEDIUM] HOZ-FW-003 - fail2ban ausente
10. [MEDIUM] HOZ-UPD-002 - Reboot pendiente

## 1. [CRITICAL] HOZ-SSH-BUNDLE (HOZ-SSH-001+HOZ-SSH-002) - Endurecer SSH (drop-in)

PermitRootLogin yes.; PasswordAuthentication yes.

```text
PermitRootLogin no
PasswordAuthentication no
```

Antes:
- Entrá con un usuario sudo + key en OTRA sesión y dejala abierta.
- id && sudo -v
- whoami   # ese es USUARIO; no inventamos el user si no viene en el JSON
- Host del reporte: cliente-wp-07
- Probá desde otra máquina: ssh -o BatchMode=yes USUARIO@cliente-wp-07 true

**LOCKOUT: si cortás root/password sin usuario sudo + key, te quedás afuera.**

```bash
sudo mkdir -p /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/99-hozfix.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
EOF
sudo sshd -t
sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh
```

Verificar:

```bash
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries'
ls -la /etc/ssh/sshd_config.d/99-hozfix.conf
```

Un solo drop-in con: HOZ-SSH-001, HOZ-SSH-002. Archivo: /etc/ssh/sshd_config.d/99-hozfix.conf

## 2. [CRITICAL] HOZ-WEB-001 - .env legible en docroot

/var/www/html/.env es legible por otros (0o644).

```text
/var/www/html/.env 0o644
```

```bash
sudo chmod 600 /var/www/html/.env
sudo chown root:root /var/www/html/.env 2>/dev/null || true
ls -la /var/www/html/.env
```

Verificar:

```bash
ls -la /var/www/html/.env
stat -c '%a %n' /var/www/html/.env
```

Path del hallazgo: /var/www/html/.env. Mejor: sacalo del docroot.

## 3. [HIGH] HOZ-WEB-101 - wp-config.php con permisos flojos

/var/www/html/wp-config.php mode 0o664.

```text
/var/www/html/wp-config.php
```

```bash
sudo chmod 640 /var/www/html/wp-config.php
sudo chown root:www-data /var/www/html/wp-config.php 2>/dev/null || sudo chown root:nginx /var/www/html/wp-config.php 2>/dev/null || true
ls -la /var/www/html/wp-config.php
```

Verificar:

```bash
ls -la /var/www/html/wp-config.php
```

Path: /var/www/html/wp-config.php.

## 4. [HIGH] HOZ-NET-004+HOZ-DB-002 - Sacar MySQL/MariaDB de internet (bind + ufw)

MariaDB/MySQL escucha en 0.0.0.0:3306 (mysqld). | bind-address = 0.0.0.0

```text
/etc/mysql/mysql.conf.d/mysqld.cnf
```

**Restart de MySQL/MariaDB corta conexiones activas.**

```bash
sudo ufw deny 3306/tcp || true
sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf
grep -n bind-address /etc/mysql/mysql.conf.d/mysqld.cnf || true
sudo systemctl restart mysql 2>/dev/null || sudo systemctl restart mariadb 2>/dev/null || true
sudo ss -lntp | grep ':3306' || true
```

Verificar:

```bash
sudo ss -lntp | grep ':3306' || true
grep -n bind-address /etc/mysql/mysql.conf.d/mysqld.cnf || true
```

Editando /etc/mysql/mysql.conf.d/mysqld.cnf (path del hallazgo). Si hay clientes remotos, túnel o allowlist. Cubre también HOZ-DB-002.

## 5. [MEDIUM] HOZ-DOCK-010 - Publish en 0.0.0.0

Hay puertos Docker publicados a interfaces públicas.

```text
mailcowdockerized-nginx-mailcow-1	mailcow/nginx:1.0	0.0.0.0:8081->80/tcp	Up 3 weeks
```

```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Image}}'
docker inspect --format '{{.Name}} {{json .HostConfig.PortBindings}}' mailcowdockerized-nginx-mailcow-1 2>/dev/null || true
```

Verificar:

```bash
docker port mailcowdockerized-nginx-mailcow-1 2>/dev/null || true
```

Contenedores del hallazgo: mailcowdockerized-nginx-mailcow-1. En compose: '127.0.0.1:HOST:CONT' y recreá.

## 6. [MEDIUM] HOZ-NET-011 - Servicio en 8080 expuesto públicamente

Servicio en 8080 escucha en 0.0.0.0:8080 (php).

```text
0.0.0.0:8080 LISTEN php
```

```bash
sudo ss -lntp | grep ':8080' || true
sudo ufw deny 8080/tcp || true
```

Verificar:

```bash
sudo ss -lntp | grep ':8080' || true
sudo ufw status | grep 8080 || true
```

Fijate qué corre ahí antes de asustarte.

## 7. [HIGH] HOZ-USR-004 - NOPASSWD en sudoers

1 línea(s) con NOPASSWD.

```text
deploy ALL=(ALL) NOPASSWD: ALL
```

```bash
sudo grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true
sudo visudo -c
```

Si no hace falta, sacá NOPASSWD o limitá al binario. Editá con visudo.

## 8. [HIGH] HOZ-FW-001 - UFW inactivo

UFW está instalado pero inactive.

```text
Status: inactive
```

Antes:
- Confirmá acceso por el puerto 22 desde otra sesión.
- sudo ufw status | grep -E '22|Status' || true

**LOCKOUT: ufw --force enable sin allow 22/tcp te corta el SSH.**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'ssh'
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
```

Verificar:

```bash
sudo ufw status verbose
sudo ss -lntp | grep ':22' || true
```

Allow SSH en 22/tcp (del reporte HOZ-SSH-005 si venía). Si tus apps usan otros puertos, agregalos ANTES del enable.

## 9. [MEDIUM] HOZ-FW-003 - fail2ban ausente

No encontré fail2ban.

```bash
sudo apt-get update && sudo apt-get install -y fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd || sudo fail2ban-client status
```

Verificar:

```bash
sudo fail2ban-client status sshd || true
```

Puerto SSH del reporte: 22. Mejor combo: keys + PasswordAuthentication no.

## 10. [MEDIUM] HOZ-UPD-002 - Reboot pendiente

Existe /var/run/reboot-required.

```text
linux-image-5.15.0-119-generic
linux-base
```

```bash
cat /var/run/reboot-required 2>/dev/null || true
cat /var/run/reboot-required.pkgs 2>/dev/null || true
# sudo reboot
```

Agendá ventana. Descomentá el reboot cuando puedas.
