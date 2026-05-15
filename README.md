<div align="center">

```
███╗   ███╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔████╔██║██║   ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
██║╚██╔╝██║██║   ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚═╝ ██║╚██████╔╝██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Script de reconhecimento para pentest — sem dependências externas**

![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/Licença-MIT-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Plataforma-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Ativo-brightgreen?style=flat-square)

</div>

---

## Sobre o projeto

O **MoreScan** é um script Bash de reconhecimento para pentest que executa as principais etapas de enumeração de um alvo sem depender de ferramentas externas instaladas. Tudo é feito com recursos nativos do Linux — `curl`, `jq`, `openssl` e os próprios mecanismos do bash, tornando o script portável, leve e pronto para rodar em qualquer ambiente.

O script foi pensado para profissionais de segurança ofensiva e estudantes que precisam de uma ferramenta de reconhecimento rápida, organizada e sem overhead de instalação.

> ⚠️ **Aviso legal:** o MoreScan deve ser utilizado **exclusivamente em ambientes nos quais você possui autorização explícita** para realizar testes. O uso não autorizado contra sistemas de terceiros é ilegal. O autor não se responsabiliza por uso indevido desta ferramenta.

---

## Funcionalidades

| # | Módulo | O que faz |
|---|--------|-----------|
| 1 | **Enumeração de Subdomínios** | Consulta 7 fontes OSINT públicas (crt.sh, HackerTarget, RapidDNS, AlienVault OTX, BufferOver, Wayback Machine, ThreatCrowd) e realiza força bruta DNS leve via `getent` |
| 2 | **Mapeamento de Diretórios** | Testa mais de 200 caminhos sensíveis conhecidos (arquivos de config, backups, painéis admin, CI/CD exposto, logs, frameworks) e salva status e tamanho de cada resposta |
| 3 | **Port Scan** | Escaneia mais de 70 portas comuns em paralelo via `/dev/tcp` nativo do bash, identifica o serviço em cada porta e realiza banner grabbing |
| 4 | **Fingerprint de Tecnologias** | Detecta stack tecnológica via análise de headers HTTP, HTML, meta tags, scripts JS externos, certificado SSL/TLS, registros DNS e WHOIS |
| 5 | **Enumeração de APIs** | Testa mais de 150 endpoints REST/GraphQL conhecidos, tenta introspection GraphQL, busca specs OpenAPI/Swagger, verifica subdomínios de API e testa misconfigurações de CORS |

---

## Como funciona

Ao executar o script, ele apresenta um banner interativo e solicita duas informações:

**1 — Ordem de execução dos módulos**

O usuário digita os números dos módulos na ordem desejada. Por exemplo:

```
32514  →  Port Scan → Mapeamento → Subdomínios → Fingerprint → APIs
1      →  Apenas Enumeração de Subdomínios
12345  →  Todos os módulos na ordem padrão
```

**2 — Domínio alvo**

```
Domínio principal a ser escaneado: exemplo.com
```

O script então cria automaticamente uma pasta com o nome `exemplo.comMoreScan/` e salva cada resultado em um arquivo `.txt` separado dentro dela.

```
exemplo.comMoreScan/
├── enumeracaoSubdominios.txt
├── mapeamentoDir.txt
├── portScan.txt
├── fingerprintTecnologias.txt
└── enumeracaoAPIs.txt
```

---

## Instalação e uso

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/morescan.git
cd morescan

# Dê permissão de execução
chmod +x morescan.sh

# Execute
bash morescan.sh
```

### Dependências

O MoreScan não requer instalação de ferramentas de pentest. As únicas dependências são utilitários padrão presentes em praticamente qualquer distribuição Linux:

| Ferramenta | Finalidade | Presente por padrão |
|------------|------------|---------------------|
| `curl` | Requisições HTTP | ✅ Sim |
| `jq` | Parse de JSON | ✅ Sim (maioria das distros) |
| `openssl` | Inspeção de SSL/TLS | ✅ Sim |
| `bash 5+` | `/dev/tcp`, paralelismo | ✅ Sim |
| `getent` | Resolução DNS | ✅ Sim (glibc) |

Caso `jq` não esteja instalado:

```bash
sudo apt install jq -y      # Debian/Ubuntu
sudo yum install jq -y      # CentOS/RHEL
sudo pacman -S jq           # Arch Linux
brew install jq             # macOS
```

---

## Exemplo de saída

```
━━━  Port Scan com Identificação de Serviços  ━━━

[*] Escaneando 72 portas em exemplo.com (192.168.1.1)...
[+] Porta 22/tcp  — SSH    — ABERTA
[+] Porta 80/tcp  — HTTP   — ABERTA
[+] Porta 443/tcp — HTTPS  — ABERTA
[+] Porta 3306/tcp — MySQL — ABERTA
[+] Total: 4 portas abertas
```

```
━━━  Fingerprint de Tecnologias  ━━━

[*] Analisando headers de tecnologia...
  ✓ Nginx
  ✓ PHP
  ✓ WordPress
  ✓ Cloudflare CDN
  ✓ HSTS habilitado
[+] Tecnologias detectadas: 5
```

---

## Estrutura do projeto

```
morescan/
├── morescan.sh       # Script principal
└── README.md         # Documentação
```

---

## Contribuindo

Contribuições são bem-vindas! Para sugerir melhorias, abrir issues ou enviar pull requests:

1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas alterações (`git commit -m 'feat: adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

---

<div align="center">
Feito para a comunidade de segurança ofensiva. Use com responsabilidade.
</div>
