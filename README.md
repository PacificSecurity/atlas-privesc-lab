# Desafio de Elevação de Privilégios no Linux (container)

Laboratório prático de **elevação de privilégios local** em um container Linux. Você entra
como o usuário comum **`analista`** e precisa encontrar **cinco caminhos diferentes e
independentes** para elevar privilégios até **`root`** dentro do container.

Os caminhos **não são indicados**: a proposta é investigar o ambiente em modo *black box*,
encontrar cada falha, explorá-la e obter uma evidência do privilégio alcançado. As cinco
falhas são independentes: cada uma leva a root por conta própria.

> Laboratório educacional e autocontido. Explore **somente** este container descartável. As
> técnicas aqui servem para estudo de **defesa e hardening** de Linux; não as use fora de um
> ambiente autorizado.

## Como preparar o laboratório

Você só precisa do **Docker** instalado e funcionando. Tudo roda dentro do container, sem
acesso à rede (`--network none`).

### Baixar a imagem

- **Link:** <https://atividade-preselec-pacsec.s3.us-east-1.amazonaws.com/pos/linux/linux-desafio-v2-amd64.tar>
- **Nome do arquivo:** `linux-desafio-v2-amd64.tar`
- **SHA-256 esperado:** `0f9e7de0a8300bbde622ddc6faf2a461200181bce652166bdca65fbb8ab14024`

Confira o hash e importe a imagem:

```bash
sha256sum linux-desafio-v2-amd64.tar
```

```bash
docker load -i linux-desafio-v2-amd64.tar
```

### Iniciar o container

```bash
docker run --rm -it --platform linux/amd64 --network none \
  --hostname priv-esc-lab --add-host priv-esc-lab:127.0.0.1 \
  --pids-limit 128 --memory 768m \
  priv-esc-linux-desafio:v2-amd64
```

O terminal abre direto como **`analista`** (não precisa de senha). Para sair, digite `exit` e
o container é removido. Para recomeçar do zero, rode o mesmo `docker run`.

> **Dica:** como cada `docker run` cria um container limpo, **suba um container novo antes de
> testar cada caminho**. Cada vetor deve funcionar sozinho, a partir do estado original.

## Regras da investigação

A atividade é **black box**. Investigue os programas, arquivos, permissões e processos de
dentro do container, usando o acesso do usuário `analista`. Não inspecione a imagem Docker,
suas camadas, o Dockerfile ou os arquivos de construção para obter as respostas. Não use
`docker exec -u root`, `--privileged`, volumes, o socket do Docker ou recursos do host como
forma de ganhar privilégio: os cinco caminhos procurados são internos ao laboratório.

## Solução

Tentou, travou, ou quer conferir sua abordagem? O passo a passo completo dos cinco vetores,
com os comandos e as evidências, está no **[writeup.md](writeup.md)**.

> ⚠️ **Spoiler:** o writeup entrega todos os caminhos. Tente sozinho primeiro, é onde está o
> aprendizado.

Bons estudos.
