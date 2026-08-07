# Seguridad

## Reportar

Mandá un mail a briandlhz@proton.me con "hozfix" en el asunto. No abras un issue público para algo explotable.

Incluí qué versión usaste, el JSON de entrada (sacale lo sensible) y qué salió mal.

Contesto en unos días. Esto lo mantengo yo solo, no esperes SLA de empresa.

## Qué cuenta

Hozfix genera comandos que corrés con sudo. Lo grave es que el plan haga algo distinto de lo que dice:

- Inyección de comandos desde el JSON de Hoztage (paths, usuarios, nombres de contenedor).
- Un fix que te deje afuera del server sin avisarlo en los prerequisitos.
- Un fix que abra algo en vez de cerrarlo.

## Qué no

- Que falte una receta para un finding. Eso es un issue.
- Que el plan pida sudo. Arreglar un server pide sudo.

## Antes de correr el plan

Leelo. Hozfix imprime comandos, no los ejecuta por vos. Si un fix toca SSH, dejá otra sesión abierta.

## Versiones

Se arregla sobre `main`. No hay backports.
