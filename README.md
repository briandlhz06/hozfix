# Hozfix

Hoztage te dijo qué está mal. Esto lee ese reporte (o IDs sueltos) y te arma un plan con comandos para arreglarlo en Ubuntu: prerequisitos, orden, verificación.

Parte de la Trilogía VPS (día 2). Antes: [Hoztage](https://github.com/briandlhz06/hoztage). Después: [Parole](https://github.com/briandlhz06/parole).

```bash
pip install "git+https://github.com/briandlhz06/hozfix.git"
python -m hozfix --from-json reporte.json
python -m hozfix --ids HOZ-SSH-001,HOZ-NET-004
python -m hozfix --from-json reporte.json --md fixes.md --sh fix.sh
python -m hozfix --from-json reporte.json --dry-run
```

Usa el contexto del hallazgo (paths, puerto SSH, users, contenedores). Drop-ins de sshd, no sed al config principal.
Orden del plan: acceso SSH -> datos/servicios -> perímetro (UFW/fail2ban) -> updates/reboot.

Por defecto solo critical / high / medium. Con `--all` también mira info si hay receta.
Varios SSH se juntan en un drop-in. NET-004 + DB-002 se deduplican. FW-003 + AUTH-001 también.

`--dry-run` imprime el plan y no escribe archivos. El `.sh` acepta `bash fix.sh --dry-run`.

## Flujo

```bash
python -m hoztage --json reporte.json
python -m hozfix --from-json reporte.json --md fixes.md --sh fix.sh
# despues de dejar el VPS sano:
python -m parole init
python -m parole check
```

[`examples/sample-fixes.md`](examples/sample-fixes.md) - input: [`examples/sample-input.json`](examples/sample-input.json)

## Exit

`0` ok. `1` error de lectura. `2` mal uso de CLI.

MIT - [Brian De La Hoz](https://briandlhz.space)
