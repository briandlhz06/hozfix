#!/usr/bin/env bash
# Hozfix: plan sugerido. Revisá antes de pegar en prod.
# Uso: sudo bash fix.sh   |   bash fix.sh --dry-run
# run_sh usa bash -c (sin eval). apply_block usa bash -s sobre el heredoc.
set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

run_sh() {
  if [[ "$DRY" == "1" ]]; then
    printf "+ %s\n" "$1"
    return 0
  fi
  bash -c "$1"
}

apply_block() {
  if [[ "$DRY" == "1" ]]; then
    printf "+ (bloque)\n"
    cat
    return 0
  fi
  bash -s
}

# host: cliente-wp-07

# 1. [CRITICAL] HOZ-SSH-BUNDLE - Endurecer SSH (drop-in)
# WARN: LOCKOUT: si cortás root/password sin usuario sudo + key, te quedás afuera.
# antes: Entrá con un usuario sudo + key en OTRA sesión y dejala abierta.
# antes: id && sudo -v
# antes: whoami   # ese es USUARIO; no inventamos el user si no viene en el JSON
# antes: Host del reporte: cliente-wp-07
# antes: Probá desde otra máquina: ssh -o BatchMode=yes USUARIO@cliente-wp-07 true
# Un solo drop-in con: HOZ-SSH-001, HOZ-SSH-002. Archivo: /etc/ssh/sshd_config.d/99-hozfix.conf
apply_block <<'HOZ_BLOCK'
sudo mkdir -p /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/99-hozfix.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
EOF
sudo sshd -t
sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh
HOZ_BLOCK
# verificar:
run_sh 'sudo sshd -T | grep -Ei '\''permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries'\'''
run_sh 'ls -la /etc/ssh/sshd_config.d/99-hozfix.conf'

# 2. [CRITICAL] HOZ-WEB-001 - .env legible en docroot
# Path del hallazgo: /var/www/html/.env. Mejor: sacalo del docroot.
run_sh 'sudo chmod 600 /var/www/html/.env'
run_sh 'sudo chown root:root /var/www/html/.env 2>/dev/null || true'
run_sh 'ls -la /var/www/html/.env'
# verificar:
run_sh 'ls -la /var/www/html/.env'
run_sh 'stat -c '\''%a %n'\'' /var/www/html/.env'

# 3. [HIGH] HOZ-WEB-101 - wp-config.php con permisos flojos
# Path: /var/www/html/wp-config.php.
run_sh 'sudo chmod 640 /var/www/html/wp-config.php'
run_sh 'sudo chown root:www-data /var/www/html/wp-config.php 2>/dev/null || sudo chown root:nginx /var/www/html/wp-config.php 2>/dev/null || true'
run_sh 'ls -la /var/www/html/wp-config.php'
# verificar:
run_sh 'ls -la /var/www/html/wp-config.php'

# 4. [HIGH] HOZ-NET-004 - Sacar MySQL/MariaDB de internet (bind + ufw)
# WARN: Restart de MySQL/MariaDB corta conexiones activas.
# Editando /etc/mysql/mysql.conf.d/mysqld.cnf (path del hallazgo). Si hay clientes remotos, túnel o allowlist. Cubre también HOZ-DB-002.
run_sh 'sudo ufw deny 3306/tcp || true'
run_sh 'sudo sed -i '\''s/^bind-address.*/bind-address = 127.0.0.1/'\'' /etc/mysql/mysql.conf.d/mysqld.cnf'
run_sh 'grep -n bind-address /etc/mysql/mysql.conf.d/mysqld.cnf || true'
run_sh 'sudo systemctl restart mysql 2>/dev/null || sudo systemctl restart mariadb 2>/dev/null || true'
run_sh 'sudo ss -lntp | grep '\'':3306'\'' || true'
# verificar:
run_sh 'sudo ss -lntp | grep '\'':3306'\'' || true'
run_sh 'grep -n bind-address /etc/mysql/mysql.conf.d/mysqld.cnf || true'

# 5. [MEDIUM] HOZ-DOCK-010 - Publish en 0.0.0.0
# Contenedores del hallazgo: mailcowdockerized-nginx-mailcow-1. En compose: '127.0.0.1:HOST:CONT' y recreá.
run_sh 'docker ps --format '\''table {{.Names}}\t{{.Ports}}\t{{.Image}}'\'''
run_sh 'docker inspect --format '\''{{.Name}} {{json .HostConfig.PortBindings}}'\'' mailcowdockerized-nginx-mailcow-1 2>/dev/null || true'
# verificar:
run_sh 'docker port mailcowdockerized-nginx-mailcow-1 2>/dev/null || true'

# 6. [MEDIUM] HOZ-NET-011 - Servicio en 8080 expuesto públicamente
# Fijate qué corre ahí antes de asustarte.
run_sh 'sudo ss -lntp | grep '\'':8080'\'' || true'
run_sh 'sudo ufw deny 8080/tcp || true'
# verificar:
run_sh 'sudo ss -lntp | grep '\'':8080'\'' || true'
run_sh 'sudo ufw status | grep 8080 || true'

# 7. [HIGH] HOZ-USR-004 - NOPASSWD en sudoers
# Si no hace falta, sacá NOPASSWD o limitá al binario. Editá con visudo.
run_sh 'sudo grep -Rni '\''NOPASSWD'\'' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true'
run_sh 'sudo visudo -c'

# 8. [HIGH] HOZ-FW-001 - UFW inactivo
# WARN: LOCKOUT: ufw --force enable sin allow 22/tcp te corta el SSH.
# antes: Confirmá acceso por el puerto 22 desde otra sesión.
# antes: sudo ufw status | grep -E '22|Status' || true
# Allow SSH en 22/tcp (del reporte HOZ-SSH-005 si venía). Si tus apps usan otros puertos, agregalos ANTES del enable.
run_sh 'sudo ufw default deny incoming'
run_sh 'sudo ufw default allow outgoing'
run_sh 'sudo ufw allow 22/tcp comment '\''ssh'\'''
run_sh 'sudo ufw allow 80/tcp'
run_sh 'sudo ufw allow 443/tcp'
run_sh 'sudo ufw --force enable'
run_sh 'sudo ufw status verbose'
# verificar:
run_sh 'sudo ufw status verbose'
run_sh 'sudo ss -lntp | grep '\'':22'\'' || true'

# 9. [MEDIUM] HOZ-FW-003 - fail2ban ausente
# Puerto SSH del reporte: 22. Mejor combo: keys + PasswordAuthentication no.
run_sh 'sudo apt-get update && sudo apt-get install -y fail2ban'
run_sh 'sudo systemctl enable --now fail2ban'
run_sh 'sudo fail2ban-client status sshd || sudo fail2ban-client status'
# verificar:
run_sh 'sudo fail2ban-client status sshd || true'

# 10. [MEDIUM] HOZ-UPD-002 - Reboot pendiente
# Agendá ventana. Descomentá el reboot cuando puedas.
run_sh 'cat /var/run/reboot-required 2>/dev/null || true'
run_sh 'cat /var/run/reboot-required.pkgs 2>/dev/null || true'
# sudo reboot
