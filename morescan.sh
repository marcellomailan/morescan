#!/usr/bin/env bash
# ============================================================
#  MoreScan - Script de Reconhecimento para Pentest
#  Dependências: curl, jq, openssl, bash (padrão em qualquer Linux)
#  Uso: bash morescan.sh
# ============================================================

# ── Cores ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Verificação de dependências mínimas ───────────────────────
check_deps() {
    local missing=()
    for dep in curl jq openssl bash; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[ERRO]${RESET} Dependências ausentes: ${missing[*]}"
        echo -e "       Instale com: ${CYAN}sudo apt install ${missing[*]} -y${RESET}"
        exit 1
    fi
}

# ── Utilitários ───────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[*]${RESET} $1"; }
log_ok()      { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[-]${RESET} $1"; }
log_section() { echo -e "\n${MAGENTA}${BOLD}━━━  $1  ━━━${RESET}\n"; }
timestamp()   { date '+%Y-%m-%d %H:%M:%S'; }

write_header() {
    local file="$1" title="$2"
    {
        echo "============================================================"
        echo "  MoreScan — ${title}"
        echo "  Alvo   : ${DOMAIN}"
        echo "  Data   : $(timestamp)"
        echo "============================================================"
        echo ""
    } > "$file"
}

# curl silencioso com timeout padrão e User-Agent realista
_curl() {
    curl -sk --connect-timeout 6 --max-time 12 \
        -A "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0" \
        "$@"
}

# Retorna apenas o HTTP status code
_status() {
    curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 6 --max-time 10 \
        -A "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0" \
        "$@"
}

# Resolução DNS nativa via getent (sem dig/host/nslookup)
resolve_ip() {
    local host="$1"
    getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -1
}

# Probe de porta via /dev/tcp nativo do bash
probe_port() {
    local host="$1" port="$2"
    (echo >/dev/tcp/"$host"/"$port") 2>/dev/null
}

# ── Banner ────────────────────────────────────────────────────
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ███╗   ███╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗"
    echo "  ████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║"
    echo "  ██╔████╔██║██║   ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║"
    echo "  ██║╚██╔╝██║██║   ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║"
    echo "  ██║ ╚═╝ ██║╚██████╔╝██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║"
    echo "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${RESET}"
    echo "  By CSGoblin - Marcello Mailan"
    echo ""
    echo -e "${YELLOW}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "  ${BOLD}Script para Recon${RESET}  |  ${RED}Use apenas em ambientes autorizados${RESET}"
    echo -e "${YELLOW}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Serviços disponíveis:${RESET}"
    echo ""
    echo -e "  ${GREEN}[1]${RESET} Enumeração de Subdomínios"
    echo -e "  ${GREEN}[2]${RESET} Mapeamento de Diretórios e Arquivos Sensíveis"
    echo -e "  ${GREEN}[3]${RESET} Port Scan com Identificação de Serviços"
    echo -e "  ${GREEN}[4]${RESET} Fingerprint de Tecnologias"
    echo -e "  ${GREEN}[5]${RESET} Enumeração de APIs"
    echo ""
    echo -e "${YELLOW}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

# ═════════════════════════════════════════════════════════════
# 1 — ENUMERAÇÃO DE SUBDOMÍNIOS
# Fontes: crt.sh · HackerTarget · RapidDNS · AlienVault OTX
#         BufferOver · Wayback Machine · ThreatCrowd
#         + DNS brute force nativo (bash /dev/tcp + getent)
# ═════════════════════════════════════════════════════════════
run_subdomain_enum() {
    local outfile="${OUTPUT_DIR}/enumeracaoSubdominios.txt"
    log_section "Enumeração de Subdomínios"
    write_header "$outfile" "Enumeração de Subdomínios"

    declare -A seen=()
    local found=()

    # Adiciona subdomínio à lista deduplicada
    collect() {
        local src="$1"; shift
        local new=0
        for s in "$@"; do
            s=$(echo "$s" | tr '[:upper:]' '[:lower:]' \
                | sed 's/\*\.//g; s/^\.//; s/[[:space:]]//g')
            [[ "$s" == *"${DOMAIN}" ]] || continue
            [[ "$s" == "$DOMAIN" ]]   && continue
            [[ -z "${seen[$s]:-}" ]]  || continue
            seen[$s]=1
            found+=("$s")
            ((new++))
        done
        [ $new -gt 0 ] && log_ok "${src}: ${new} novos subdomínios"
    }

    # 1. crt.sh
    log_info "Consultando crt.sh..."
    local crt
    crt=$(_curl "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null)
    if [ -n "$crt" ]; then
        mapfile -t _tmp < <(echo "$crt" | jq -r '.[].name_value' 2>/dev/null \
            | tr ',' '\n' | sed 's/\*\.//g' | sort -u)
        collect "crt.sh" "${_tmp[@]}"
    fi

    # 2. HackerTarget
    log_info "Consultando HackerTarget..."
    mapfile -t _tmp < <(_curl \
        "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
        | cut -d',' -f1 | grep -v "^API\|error\|^$" | sort -u)
    collect "HackerTarget" "${_tmp[@]}"

    # 3. RapidDNS
    log_info "Consultando RapidDNS..."
    mapfile -t _tmp < <(_curl \
        "https://rapiddns.io/subdomain/${DOMAIN}?full=1&down=1" 2>/dev/null \
        | grep -oP "[\w.-]+\.${DOMAIN}" | sort -u)
    collect "RapidDNS" "${_tmp[@]}"

    # 4. AlienVault OTX
    log_info "Consultando AlienVault OTX..."
    local otx
    otx=$(_curl \
        "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" \
        2>/dev/null)
    if [ -n "$otx" ]; then
        mapfile -t _tmp < <(echo "$otx" \
            | jq -r '.passive_dns[].hostname' 2>/dev/null | sort -u)
        collect "AlienVault OTX" "${_tmp[@]}"
    fi

    # 5. BufferOver
    log_info "Consultando BufferOver..."
    local bov
    bov=$(_curl "https://tls.bufferover.run/dns?q=.${DOMAIN}" 2>/dev/null)
    if [ -n "$bov" ]; then
        mapfile -t _tmp < <(echo "$bov" \
            | jq -r '.Results[]?' 2>/dev/null \
            | grep -oP "[\w.-]+\.${DOMAIN}" | sort -u)
        collect "BufferOver" "${_tmp[@]}"
    fi

    # 6. Wayback Machine CDX
    log_info "Consultando Wayback Machine..."
    mapfile -t _tmp < <(_curl \
        "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey" \
        2>/dev/null \
        | grep -oP "[\w.-]+\.${DOMAIN}" | sort -u)
    collect "Wayback Machine" "${_tmp[@]}"

    # 7. ThreatCrowd
    log_info "Consultando ThreatCrowd..."
    local tc
    tc=$(_curl \
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${DOMAIN}" \
        2>/dev/null)
    if [ -n "$tc" ]; then
        mapfile -t _tmp < <(echo "$tc" \
            | jq -r '.subdomains[]?' 2>/dev/null | sort -u)
        collect "ThreatCrowd" "${_tmp[@]}"
    fi

    # 8. DNS brute force com getent (bash nativo — sem dig)
    log_info "Força bruta DNS nativa (getent)..."
    local COMMON_SUBS=(
        www mail ftp smtp pop pop3 imap webmail cpanel whm
        admin administrator panel dashboard portal login
        api api2 rest dev dev2 staging stage test beta
        app app2 mobile m static cdn assets media img images
        blog news shop store pay payment billing accounts
        secure vpn remote access intranet internal corp
        git gitlab github jenkins ci cd build deploy
        s3 bucket storage cloud backup db database
        mx mx1 mx2 ns ns1 ns2 dns dns1 dns2
        autodiscover autoconfig owa exchange
        help support ticket jira confluence wiki
        v1 v2 v3 old legacy new preview sandbox
        marketing crm erp analytics data monitor status health
    )
    local brute_new=0
    for sub in "${COMMON_SUBS[@]}"; do
        local fqdn="${sub}.${DOMAIN}"
        local ip
        ip=$(resolve_ip "$fqdn")
        if [ -n "$ip" ] && [[ -z "${seen[$fqdn]:-}" ]]; then
            seen[$fqdn]=1
            found+=("$fqdn")
            ((brute_new++))
        fi
    done
    [ $brute_new -gt 0 ] && log_ok "DNS brute force: ${brute_new} novos subdomínios"

    # ── Escreve resultado ──────────────────────────────────────
    {
        echo "── Subdomínios encontrados: ${#found[@]} únicos ───────────────────"
        echo ""
        printf "  %-45s  %s\n" "SUBDOMÍNIO" "IP RESOLVIDO"
        printf "  %-45s  %s\n" \
            "─────────────────────────────────────────────" "───────────────"
    } >> "$outfile"

    if [ ${#found[@]} -eq 0 ]; then
        echo "  Nenhum subdomínio encontrado." >> "$outfile"
    else
        for sub in $(printf '%s\n' "${found[@]}" | sort -u); do
            local ip
            ip=$(resolve_ip "$sub")
            [ -z "$ip" ] && ip="(não resolvido)"
            printf "  %-45s  %s\n" "$sub" "$ip" >> "$outfile"
        done
    fi

    echo "" >> "$outfile"
    log_ok "Concluído → ${outfile}"
    log_ok "Total: ${#found[@]} subdomínios únicos"
}

# ═════════════════════════════════════════════════════════════
# 2 — MAPEAMENTO DE DIRETÓRIOS E ARQUIVOS SENSÍVEIS
# Método: curl nativo (sem ffuf/gobuster/dirb)
# ═════════════════════════════════════════════════════════════
run_dir_mapping() {
    local outfile="${OUTPUT_DIR}/mapeamentoDir.txt"
    log_section "Mapeamento de Diretórios e Arquivos Sensíveis"
    write_header "$outfile" "Mapeamento de Diretórios"

    # Detecta protocolo
    local BASE="https://${DOMAIN}"
    [[ "$(_status "$BASE/")" == "000" ]] && BASE="http://${DOMAIN}"
    log_info "Base: ${BASE}"

    local PATHS=(
        # ── Configuração e credenciais ──
        "/.env"                         "/.env.local"
        "/.env.dev"                     "/.env.development"
        "/.env.prod"                    "/.env.production"
        "/.env.staging"                 "/.env.backup"
        "/.env.bak"                     "/.env.old"
        "/.env.example"                 "/.env.sample"
        "/config.php"                   "/config.php.bak"
        "/configuration.php"            "/config.inc.php"
        "/config.yml"                   "/config.yaml"
        "/config.json"                  "/config.xml"
        "/config.ini"                   "/config.cfg"
        "/app/config.php"               "/application/config.php"
        "/wp-config.php"                "/wp-config.php.bak"
        "/wp-config.php.orig"           "/wp-config.bak"
        "/web.config"                   "/Web.config"
        "/application.properties"       "/application.yml"
        "/application.yaml"             "/application-dev.properties"
        "/application-prod.properties"
        "/database.yml"                 "/database.php"
        "/db.php"                       "/db.yml"
        "/settings.php"                 "/settings.py"
        "/local_settings.py"            "/settings_local.py"
        "/secrets.yml"                  "/secrets.yaml"
        "/credentials.json"             "/auth.json"
        "/.htpasswd"                    "/htpasswd"
        "/.npmrc"                       "/.pypirc"
        "/.netrc"                       "/.pgpass"
        "/sftp-config.json"

        # ── Backup e dumps ──
        "/backup.zip"                   "/backup.tar.gz"
        "/backup.tar"                   "/backup.sql"
        "/backup.sql.gz"                "/backup.db"
        "/backup/"                      "/backups/"
        "/bkp/"                         "/bkp.zip"
        "/old.zip"                      "/old/"
        "/archive.zip"                  "/dump.sql"
        "/dump.sql.gz"                  "/db.sql"
        "/database.sql"                 "/data.sql"
        "/data.zip"                     "/${DOMAIN}.zip"
        "/${DOMAIN}.tar.gz"             "/www.zip"
        "/website.zip"                  "/html.zip"
        "/public_html.zip"              "/htdocs.zip"

        # ── Painéis de administração ──
        "/admin"                        "/admin/"
        "/admin/login"                  "/admin/login.php"
        "/admin/index.php"              "/admin/dashboard"
        "/administrator"                "/administrator/"
        "/administrator/index.php"      "/adminpanel"
        "/panel"                        "/panel/"
        "/dashboard"                    "/dashboard/"
        "/manage"                       "/management"
        "/control"                      "/controlpanel"
        "/cpanel"                       "/wp-admin"
        "/wp-admin/"                    "/wp-login.php"
        "/wp-login"                     "/phpmyadmin"
        "/phpmyadmin/"                  "/pma"
        "/pma/"                         "/phpMyAdmin"
        "/myadmin"                      "/mysql"
        "/mysqladmin"                   "/sqladmin"
        "/adminer"                      "/adminer.php"
        "/filemanager"                  "/filemanager/"
        "/webmin"                       "/webadmin"
        "/siteadmin"                    "/manager"
        "/manager/"                     "/console"
        "/server-manager"               "/system"
        "/portal"                       "/portal/"
        "/backend"                      "/backend/"
        "/secure"                       "/private"
        "/internal"                     "/staff"
        "/moderator"                    "/superadmin"

        # ── VCS e CI/CD expostos ──
        "/.git/HEAD"                    "/.git/config"
        "/.git/COMMIT_EDITMSG"          "/.git/index"
        "/.git/packed-refs"             "/.git/refs/heads/master"
        "/.git/refs/heads/main"         "/.git/logs/HEAD"
        "/.gitignore"                   "/.gitattributes"
        "/.gitlab-ci.yml"               "/.travis.yml"
        "/Jenkinsfile"                  "/.circleci/config.yml"
        "/bitbucket-pipelines.yml"      "/azure-pipelines.yml"
        "/Dockerfile"                   "/docker-compose.yml"
        "/docker-compose.yaml"          "/docker-compose.prod.yml"
        "/.dockerignore"                "/Makefile"
        "/Vagrantfile"                  "/terraform.tfstate"
        "/terraform.tfvars"

        # ── Logs e debug ──
        "/error.log"                    "/error_log"
        "/access.log"                   "/access_log"
        "/debug.log"                    "/debug.txt"
        "/app.log"                      "/application.log"
        "/server.log"                   "/php_error.log"
        "/php_errors.log"               "/laravel.log"
        "/storage/logs/laravel.log"     "/logs/"
        "/log/"                         "/logs/error.log"
        "/logs/access.log"              "/tmp/"
        "/temp/"                        "/cache/"

        # ── PHP info / diagnóstico ──
        "/info.php"                     "/phpinfo.php"
        "/phpinfo"                      "/test.php"
        "/test.html"                    "/check.php"
        "/status.php"                   "/server-status"
        "/server-info"                  "/.htaccess"
        "/php.ini"

        # ── Documentação e metadados ──
        "/README.md"                    "/README.txt"
        "/CHANGELOG.md"                 "/CHANGELOG.txt"
        "/TODO"                         "/TODO.md"
        "/INSTALL.md"                   "/LICENSE"
        "/robots.txt"                   "/sitemap.xml"
        "/sitemap_index.xml"            "/crossdomain.xml"
        "/clientaccesspolicy.xml"       "/humans.txt"
        "/security.txt"                 "/.well-known/security.txt"

        # ── Cloud e infra ──
        "/.aws/credentials"             "/.aws/config"
        "/.ssh/id_rsa"                  "/.ssh/authorized_keys"
        "/.ssh/known_hosts"             "/.bash_history"
        "/.bashrc"                      "/.profile"

        # ── Package managers ──
        "/package.json"                 "/package-lock.json"
        "/yarn.lock"                    "/composer.json"
        "/composer.lock"                "/Gemfile"
        "/Gemfile.lock"                 "/requirements.txt"
        "/Pipfile"                      "/go.mod"
        "/pom.xml"                      "/build.gradle"

        # ── Frameworks específicos ──
        # Laravel
        "/artisan"                      "/storage/app/public"
        # Spring Boot Actuator
        "/actuator"                     "/actuator/health"
        "/actuator/env"                 "/actuator/beans"
        "/actuator/mappings"            "/actuator/metrics"
        "/actuator/heapdump"            "/actuator/threaddump"
        "/actuator/shutdown"            "/h2-console"
        # Rails
        "/rails/info"                   "/rails/info/properties"
        # Uploads e estáticos
        "/upload"                       "/upload/"
        "/uploads"                      "/uploads/"
        "/files"                        "/files/"
        "/static"                       "/assets"
        "/media"                        "/dist"
        "/build"                        "/public"
    )

    local found_count=0
    {
        printf "  %-7s  %-55s  %s\n" "STATUS" "CAMINHO" "TAMANHO"
        printf "  %-7s  %-55s  %s\n" \
            "───────" "───────────────────────────────────────────────────────" "────────"
    } >> "$outfile"

    log_info "Testando ${#PATHS[@]} caminhos (curl nativo)..."

    for path in "${PATHS[@]}"; do
        local url="${BASE}${path}"
        local response
        response=$(curl -sk -o /dev/null \
            -w "%{http_code}|%{size_download}" \
            --connect-timeout 5 --max-time 10 \
            -A "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0" \
            -L "$url" 2>/dev/null)

        local status="${response%%|*}"
        local size="${response##*|}"

        if [[ "$status" =~ ^(200|201|204|301|302|307|400|401|403|405|500)$ ]]; then
            printf "  %-7s  %-55s  %s bytes\n" \
                "[$status]" "$path" "$size" >> "$outfile"
            log_ok "[$status] $path (${size}B)"
            ((found_count++))
        fi
    done

    {
        echo ""
        echo "── Total: ${found_count} caminhos com resposta ──────────────────────"
        echo ""
    } >> "$outfile"

    # Conteúdo completo de robots.txt e sitemap
    log_info "Baixando robots.txt..."
    {
        echo "── robots.txt ──────────────────────────────────────────────"
        _curl "${BASE}/robots.txt" 2>/dev/null | head -80
        echo ""
    } >> "$outfile"

    log_info "Baixando sitemap.xml (primeiras 50 URLs)..."
    {
        echo "── sitemap.xml ─────────────────────────────────────────────"
        _curl "${BASE}/sitemap.xml" 2>/dev/null \
            | grep -oP 'https?://[^<"]+' | head -50
        echo ""
    } >> "$outfile"

    log_ok "Concluído → ${outfile}"
    log_ok "Total: ${found_count} caminhos com resposta"
}

# ═════════════════════════════════════════════════════════════
# 3 — PORT SCAN
# Método: /dev/tcp nativo do bash (paralelo) + banner grabbing
# ═════════════════════════════════════════════════════════════
run_portscan() {
    local outfile="${OUTPUT_DIR}/portScan.txt"
    log_section "Port Scan com Identificação de Serviços"
    write_header "$outfile" "Port Scan"

    declare -A SERVICE_MAP=(
        [21]="FTP"                  [22]="SSH"
        [23]="Telnet"               [25]="SMTP"
        [53]="DNS"                  [67]="DHCP"
        [69]="TFTP"                 [79]="Finger"
        [80]="HTTP"                 [88]="Kerberos"
        [110]="POP3"                [111]="RPC"
        [119]="NNTP"                [123]="NTP"
        [135]="MS-RPC"              [137]="NetBIOS-NS"
        [138]="NetBIOS-DGM"         [139]="NetBIOS-SSN"
        [143]="IMAP"                [161]="SNMP"
        [162]="SNMP-Trap"           [179]="BGP"
        [194]="IRC"                 [389]="LDAP"
        [443]="HTTPS"               [445]="SMB"
        [465]="SMTPS"               [500]="IKE/IPSec"
        [512]="rexec"               [513]="rlogin"
        [514]="syslog/rsh"          [515]="LPD"
        [587]="SMTP-Submission"     [593]="HTTP-RPC"
        [631]="IPP/CUPS"            [636]="LDAPS"
        [873]="rsync"               [902]="VMware-ESXi"
        [993]="IMAPS"               [995]="POP3S"
        [1080]="SOCKS5"             [1194]="OpenVPN"
        [1433]="MSSQL"              [1521]="Oracle-DB"
        [1723]="PPTP"               [2049]="NFS"
        [2082]="cPanel-HTTP"        [2083]="cPanel-HTTPS"
        [2086]="WHM-HTTP"           [2087]="WHM-HTTPS"
        [2181]="ZooKeeper"          [2375]="Docker-API"
        [2376]="Docker-TLS"         [2379]="etcd"
        [3000]="Node/Grafana"       [3306]="MySQL"
        [3389]="RDP"                [3690]="SVN"
        [4000]="Node/Dev"           [4200]="Angular-Dev"
        [4369]="RabbitMQ-EPMD"      [4444]="Metasploit"
        [5000]="Flask/Dev"          [5432]="PostgreSQL"
        [5601]="Kibana"             [5672]="RabbitMQ-AMQP"
        [5900]="VNC"                [5984]="CouchDB"
        [6000]="X11"                [6379]="Redis"
        [6443]="Kubernetes-API"     [7001]="WebLogic"
        [7199]="Cassandra-JMX"      [7474]="Neo4j"
        [8000]="HTTP-Alt"           [8008]="HTTP-Alt"
        [8080]="HTTP-Proxy"         [8081]="HTTP-Alt"
        [8082]="HTTP-Alt"           [8083]="HTTP-Alt"
        [8085]="HTTP-Alt"           [8086]="InfluxDB"
        [8088]="HTTP-Alt"           [8090]="Confluence"
        [8091]="Couchbase"          [8161]="ActiveMQ"
        [8443]="HTTPS-Alt"          [8444]="HTTPS-Alt"
        [8500]="Consul"             [8545]="Ethereum-RPC"
        [8888]="Jupyter/HTTP-Alt"   [8983]="Solr"
        [9000]="PHP-FPM/Portainer"  [9001]="Supervisor"
        [9090]="Prometheus"         [9092]="Kafka"
        [9200]="Elasticsearch"      [9300]="Elasticsearch-Cluster"
        [9418]="Git"                [9999]="HTTP-Alt"
        [10000]="Webmin"            [11211]="Memcached"
        [15672]="RabbitMQ-Mgmt"     [27017]="MongoDB"
        [27018]="MongoDB-Shard"     [27019]="MongoDB-Config"
        [28017]="MongoDB-Web"       [50000]="SAP"
        [50070]="Hadoop-NameNode"   [61616]="ActiveMQ-OpenWire"
    )

    local PORTS=($(for p in "${!SERVICE_MAP[@]}"; do echo "$p"; done | sort -n))

    local ip
    ip=$(resolve_ip "$DOMAIN")
    {
        echo "IP resolvido : ${ip:-não resolvido}"
        echo "Portas alvo  : ${#PORTS[@]} portas"
        echo "Método       : /dev/tcp nativo bash (paralelo)"
        echo ""
        printf "  %-8s  %-25s  %s\n" "PORTA" "SERVIÇO" "ESTADO"
        printf "  %-8s  %-25s  %s\n" \
            "────────" "─────────────────────────" "──────"
    } >> "$outfile"

    log_info "Escaneando ${#PORTS[@]} portas em ${DOMAIN} (${ip:-?})..."

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Worker paralelo — um subshell por porta
    _probe_worker() {
        local host="$1" port="$2" svc="$3" tmpdir="$4"
        if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
            echo "${port}|${svc}|ABERTA" > "${tmpdir}/${port}.result"
        fi
    }

    local batch=0 max_batch=80
    for port in "${PORTS[@]}"; do
        _probe_worker "$DOMAIN" "$port" "${SERVICE_MAP[$port]}" "$tmp_dir" &
        ((batch++))
        if (( batch >= max_batch )); then
            wait; batch=0
        fi
    done
    wait

    # Coleta e escreve resultado ordenado
    local open_count=0
    local open_ports=()
    for port in "${PORTS[@]}"; do
        local rfile="${tmp_dir}/${port}.result"
        if [ -f "$rfile" ]; then
            IFS='|' read -r p svc state < "$rfile"
            printf "  %-8s  %-25s  %s\n" "${p}/tcp" "$svc" "$state" >> "$outfile"
            log_ok "Porta ${p}/tcp — ${svc} — ABERTA"
            open_ports+=("$p")
            ((open_count++))
        fi
    done

    rm -rf "$tmp_dir"

    # ── Banner grabbing nas portas abertas ─────────────────────
    if [ ${#open_ports[@]} -gt 0 ]; then
        log_info "Banner grabbing nas portas abertas..."
        {
            echo ""
            echo "── Banner Grabbing ─────────────────────────────────────────"
            echo ""
        } >> "$outfile"

        for port in "${open_ports[@]}"; do
            local svc="${SERVICE_MAP[$port]}"
            local banner=""

            if [[ "$port" =~ ^(80|8080|8000|8008|8081|8082|8083|8085|8088|8090|8888|9000|9090|10000)$ ]]; then
                banner=$(curl -sk -I --connect-timeout 5 --max-time 8 \
                    -A "Mozilla/5.0" "http://${DOMAIN}:${port}/" 2>/dev/null \
                    | grep -iE "^(Server|X-Powered-By|Content-Type|Location|Via):" \
                    | head -6)
            elif [[ "$port" =~ ^(443|8443|8444|2083|2087)$ ]]; then
                banner=$(curl -sk -I --connect-timeout 5 --max-time 8 \
                    -A "Mozilla/5.0" "https://${DOMAIN}:${port}/" 2>/dev/null \
                    | grep -iE "^(Server|X-Powered-By|Content-Type|Location|Via):" \
                    | head -6)
            elif [[ "$port" =~ ^(22|21|25|110|143|587|993|995|23)$ ]]; then
                banner=$(timeout 3 bash -c \
                    "exec 3<>/dev/tcp/${DOMAIN}/${port}; \
                     read -t 2 line <&3 2>/dev/null; echo \"\$line\"" 2>/dev/null)
            fi

            if [ -n "$banner" ]; then
                {
                    echo "  [Porta ${port}/tcp — ${svc}]"
                    echo "$banner" | sed 's/^/    /'
                    echo ""
                } >> "$outfile"
            fi
        done
    fi

    {
        echo ""
        echo "── Resumo ──────────────────────────────────────────────────"
        echo "   Portas abertas encontradas: ${open_count}"
        echo ""
    } >> "$outfile"

    log_ok "Concluído → ${outfile}"
    log_ok "Total: ${open_count} portas abertas"
}

# ═════════════════════════════════════════════════════════════
# 4 — FINGERPRINT DE TECNOLOGIAS
# Método: curl (headers + HTML) · openssl (SSL) · DNS via API
# ═════════════════════════════════════════════════════════════
run_fingerprint() {
    local outfile="${OUTPUT_DIR}/fingerprintTecnologias.txt"
    log_section "Fingerprint de Tecnologias"
    write_header "$outfile" "Fingerprint de Tecnologias"

    local BASE_HTTPS="https://${DOMAIN}"
    local BASE_HTTP="http://${DOMAIN}"

    # ── 1. Headers HTTP completos ──────────────────────────────
    log_info "Coletando headers HTTP..."
    for proto in https http; do
        local raw
        raw=$(curl -sk -I --connect-timeout 8 --max-time 15 \
            -A "Mozilla/5.0 (X11; Linux x86_64; rv:115.0)" \
            -L "${proto}://${DOMAIN}/" 2>/dev/null)
        {
            echo "── Headers HTTP [${proto^^}] ────────────────────────────────"
            echo "$raw"
            echo ""
        } >> "$outfile"
    done

    # ── 2. Detecção via headers ────────────────────────────────
    log_info "Analisando headers de tecnologia..."
    local raw_h
    raw_h=$(curl -sk -I --connect-timeout 8 --max-time 15 \
        -A "Mozilla/5.0 (X11; Linux x86_64)" \
        -L "${BASE_HTTPS}/" 2>/dev/null)
    [ -z "$raw_h" ] && \
        raw_h=$(curl -sk -I --connect-timeout 8 --max-time 15 \
            -A "Mozilla/5.0" -L "${BASE_HTTP}/" 2>/dev/null)

    {
        echo "── Tecnologias Detectadas — Headers ───────────────────────"
        echo ""
    } >> "$outfile"

    declare -A HDR_TECH=(
        ["Server:.*[Aa]pache"]="Apache HTTP Server"
        ["Server:.*nginx"]="Nginx"
        ["Server:.*IIS"]="Microsoft IIS"
        ["Server:.*[Ll]ite[Ss]peed"]="LiteSpeed"
        ["Server:.*[Cc]addy"]="Caddy"
        ["Server:.*cloudflare"]="Cloudflare"
        ["Server:.*AmazonS3"]="Amazon S3"
        ["Server:.*openresty"]="OpenResty"
        ["Server:.*[Gg]unicorn"]="Gunicorn (Python)"
        ["Server:.*[Ww]erkzeug"]="Flask/Werkzeug (Python)"
        ["Server:.*[Kk]estrel"]="ASP.NET Core (Kestrel)"
        ["Server:.*[Ww][Ee][Bb][Rr]ick"]="Ruby WEBrick"
        ["Server:.*[Pp]uma"]="Ruby Puma"
        ["Server:.*[Jj]etty"]="Jetty (Java)"
        ["Server:.*[Tt]omcat"]="Apache Tomcat"
        ["Server:.*[Ww]eb[Ll]ogic"]="Oracle WebLogic"
        ["X-Powered-By:.*PHP"]="PHP"
        ["X-Powered-By:.*ASP.NET"]="ASP.NET"
        ["X-Powered-By:.*[Ee]xpress"]="Express.js (Node)"
        ["X-Powered-By:.*Next.js"]="Next.js"
        ["X-Powered-By:.*Nuxt"]="Nuxt.js"
        ["X-Generator:.*WordPress"]="WordPress"
        ["X-Generator:.*Drupal"]="Drupal"
        ["X-Generator:.*Joomla"]="Joomla"
        ["X-Drupal-Cache"]="Drupal"
        ["X-WordPress"]="WordPress"
        ["X-WP-Nonce"]="WordPress"
        ["X-Shopify"]="Shopify"
        ["X-Magento"]="Magento"
        ["CF-Cache-Status"]="Cloudflare CDN"
        ["CF-Ray"]="Cloudflare"
        ["X-Amz"]="Amazon AWS"
        ["X-Azure"]="Microsoft Azure"
        ["X-GFE"]="Google Frontend (GFE)"
        ["Via:.*varnish"]="Varnish Cache"
        ["Via:.*squid"]="Squid Proxy"
        ["Set-Cookie:.*PHPSESSID"]="PHP Session"
        ["Set-Cookie:.*JSESSIONID"]="Java Servlet"
        ["Set-Cookie:.*ASP.NET_SessionId"]="ASP.NET Session"
        ["Set-Cookie:.*laravel_session"]="Laravel (PHP)"
        ["Set-Cookie:.*django"]="Django (Python)"
        ["Set-Cookie:.*_rails"]="Ruby on Rails"
        ["Set-Cookie:.*wp-"]="WordPress"
        ["X-AspNet-Version"]="ASP.NET"
        ["X-AspNetMvc-Version"]="ASP.NET MVC"
        ["X-Runtime"]="Ruby on Rails (Rack)"
        ["Strict-Transport-Security"]="HSTS habilitado"
        ["Content-Security-Policy"]="CSP habilitado"
        ["X-Content-Type-Options"]="X-Content-Type-Options presente"
        ["X-Frame-Options"]="X-Frame-Options presente"
    )

    local tech_h=0
    for pattern in "${!HDR_TECH[@]}"; do
        local hdr="${pattern%%:*}"
        local rx="${pattern#*:}"
        if echo "$raw_h" | grep -iP "${hdr}:.*${rx}" &>/dev/null 2>&1; then
            echo "  ✓ ${HDR_TECH[$pattern]}" >> "$outfile"
            ((tech_h++))
        fi
    done
    [ $tech_h -eq 0 ] && echo "  Nenhuma tecnologia identificada nos headers." >> "$outfile"
    echo "" >> "$outfile"

    # ── 3. Análise do HTML ─────────────────────────────────────
    log_info "Baixando e analisando HTML da página principal..."
    local html
    html=$(_curl -L "${BASE_HTTPS}/" 2>/dev/null)
    [ -z "$html" ] && html=$(_curl -L "${BASE_HTTP}/" 2>/dev/null)

    {
        echo "── Tecnologias Detectadas — HTML ──────────────────────────"
        echo ""
    } >> "$outfile"

    declare -A HTML_TECH=(
        ["wp-content|wp-includes|/wp-json"]="WordPress"
        ["/sites/default/files|drupal\.js|Drupal\.settings"]="Drupal"
        ["joomla|/components/com_"]="Joomla"
        ["shopify|cdn\.shopify\.com"]="Shopify"
        ["magento|Mage\.Cookies"]="Magento"
        ["prestashop|/themes/classic"]="PrestaShop"
        ["wix\.com|wixstatic"]="Wix"
        ["squarespace\.com|squarespace"]="Squarespace"
        ["ghost\.org|ghost-theme"]="Ghost CMS"
        ["__NEXT_DATA__|next/static"]="Next.js"
        ["__nuxt|_nuxt/"]="Nuxt.js"
        ["gatsby|___gatsby"]="Gatsby"
        ["ReactDOM|react-dom\.min"]="React"
        ["Vue\.js|new Vue\(|vue\.min"]="Vue.js"
        ["ng-app|angular\.min\.js"]="Angular"
        ["ember\.js|Ember\.Application"]="Ember.js"
        ["backbone\.js|Backbone\.View"]="Backbone.js"
        ["jquery\.min\.js|jQuery v"]="jQuery"
        ["bootstrap\.min\.css|bootstrap\.min\.js"]="Bootstrap"
        ["tailwind|tailwindcss"]="Tailwind CSS"
        ["materialize\.min"]="Materialize CSS"
        ["font-awesome|fontawesome"]="Font Awesome"
        ["google-analytics\.com|gtag\(|GoogleAnalyticsObject"]="Google Analytics"
        ["googletagmanager\.com|GTM-"]="Google Tag Manager"
        ["pixel\.facebook\.com|fbq\("]="Facebook Pixel"
        ["hotjar\.com|hj\("]="Hotjar"
        ["intercom\.io|intercomSettings"]="Intercom"
        ["zendesk|zopim"]="Zendesk"
        ["freshchat|freshdesk"]="Freshdesk"
        ["recaptcha|google\.com/recaptcha"]="Google reCAPTCHA"
        ["hcaptcha\.com"]="hCaptcha"
        ["stripe\.com/v3|Stripe\("]="Stripe"
        ["paypal\.com/sdk|PayPalButton"]="PayPal"
        ["firebase|firebaseapp\.com"]="Firebase"
        ["sentry\.io|Sentry\.init"]="Sentry"
        ["datadog|DD_RUM"]="Datadog"
        ["newrelic\.com|newrelic"]="New Relic"
        ["swagger-ui|openapi"]="Swagger/OpenAPI"
        ["ApolloClient|apollo-client|graphql"]="GraphQL/Apollo"
        ["socket\.io\.js"]="Socket.IO"
        ["aws-sdk|amazonaws\.com"]="Amazon AWS SDK"
    )

    local tech_html=0
    for pattern in "${!HTML_TECH[@]}"; do
        if echo "$html" | grep -iP "$pattern" &>/dev/null 2>&1; then
            echo "  ✓ ${HTML_TECH[$pattern]}" >> "$outfile"
            ((tech_html++))
        fi
    done
    [ $tech_html -eq 0 ] && echo "  Nenhuma tecnologia identificada no HTML." >> "$outfile"
    echo "" >> "$outfile"

    # ── 4. Meta tags ──────────────────────────────────────────
    {
        echo "── Meta Tags ───────────────────────────────────────────────"
        echo "$html" | grep -i "<meta" | head -20 | sed 's/^/  /'
        echo ""
    } >> "$outfile"

    # ── 5. Scripts JS externos ────────────────────────────────
    {
        echo "── Scripts JS externos ─────────────────────────────────────"
        echo "$html" | grep -oP 'src=["'"'"'][^"'"'"']+\.(js|min\.js)["'"'"']' \
            | grep -v '^src=["'"'"']/' \
            | head -20 | sed 's/^/  /'
        echo ""
    } >> "$outfile"

    # ── 6. Certificado SSL ────────────────────────────────────
    log_info "Inspecionando certificado SSL..."
    {
        echo "── Certificado SSL ─────────────────────────────────────────"
        echo ""
        echo | openssl s_client -connect "${DOMAIN}:443" \
            -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout \
                -subject -issuer -dates -fingerprint -serial 2>/dev/null \
            | sed 's/^/  /'
        echo ""
        echo "  SANs (Subject Alternative Names):"
        echo | openssl s_client -connect "${DOMAIN}:443" \
            -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null \
            | grep -A1 "Subject Alternative" \
            | grep DNS | tr ',' '\n' \
            | sed 's/DNS://g; s/^[[:space:]]*/    /' | head -30
        echo ""
        echo "  Cipher Suite negociado:"
        echo | openssl s_client -connect "${DOMAIN}:443" \
            -servername "$DOMAIN" 2>/dev/null \
            | grep -E "Cipher|Protocol|Verify" | sed 's/^/    /'
        echo ""
    } >> "$outfile"

    # ── 7. Registros DNS via API (sem dig) ───────────────────
    log_info "Coletando registros DNS via API (dns.google)..."
    {
        echo "── Registros DNS ───────────────────────────────────────────"
        echo ""
    } >> "$outfile"
    for rec in A AAAA MX NS TXT CNAME SOA; do
        local dns_r
        dns_r=$(_curl \
            "https://dns.google/resolve?name=${DOMAIN}&type=${rec}" 2>/dev/null)
        local ans
        ans=$(echo "$dns_r" | jq -r \
            '.Answer[]? | "  \(.name) TTL:\(.TTL)s  \(.data)"' 2>/dev/null)
        if [ -n "$ans" ]; then
            echo "  [${rec}]" >> "$outfile"
            echo "$ans" >> "$outfile"
            echo "" >> "$outfile"
        fi
    done

    # ── 8. WHOIS via API pública ──────────────────────────────
    log_info "Consultando WHOIS..."
    {
        echo "── WHOIS ───────────────────────────────────────────────────"
        echo ""
        _curl \
            "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_demo&domainName=${DOMAIN}&outputFormat=JSON" \
            2>/dev/null | jq -r '
            .WhoisRecord |
            "  Registrant  : \(.registrant.organization // "N/A")\n" +
            "  Registrar   : \(.registrarName // "N/A")\n" +
            "  Criado em   : \(.createdDateNormalized // "N/A")\n" +
            "  Expira em   : \(.expiresDateNormalized // "N/A")\n" +
            "  Atualizado  : \(.updatedDateNormalized // "N/A")\n" +
            "  Name Servers: \((.nameServers.hostNames // []) | join(", "))"
        ' 2>/dev/null
        echo ""
    } >> "$outfile"

    log_ok "Concluído → ${outfile}"
    log_ok "Tecnologias detectadas: $((tech_h + tech_html))"
}

# ═════════════════════════════════════════════════════════════
# 5 — ENUMERAÇÃO DE APIs
# Método: curl nativo — REST · GraphQL · OpenAPI · CORS · subdomínios
# ═════════════════════════════════════════════════════════════
run_api_enum() {
    local outfile="${OUTPUT_DIR}/enumeracaoAPIs.txt"
    log_section "Enumeração de APIs"
    write_header "$outfile" "Enumeração de APIs"

    local BASE="https://${DOMAIN}"
    [[ "$(_status "$BASE/")" == "000" ]] && BASE="http://${DOMAIN}"

    # ── 1. Endpoints REST conhecidos ──────────────────────────
    log_info "Testando endpoints REST/API..."
    local API_PATHS=(
        "/api"              "/api/"             "/api/v1"
        "/api/v2"           "/api/v3"           "/api/v4"
        "/apis"             "/rest"             "/rest/v1"
        "/rest/v2"          "/rest/api"         "/service"
        "/services"         "/rpc"              "/jsonrpc"
        "/xmlrpc"           "/xmlrpc.php"       "/soap"
        "/wsdl"
        "/v1"               "/v2"               "/v3"
        "/v4"
        # Documentação
        "/swagger"          "/swagger-ui"       "/swagger-ui.html"
        "/swagger/index.html" "/swagger.json"   "/swagger.yaml"
        "/swagger/v1/swagger.json"              "/swagger/v2/swagger.json"
        "/openapi.json"     "/openapi.yaml"     "/api-docs"
        "/api-docs.json"    "/api/swagger.json" "/api/openapi.json"
        "/api/v1/swagger.json"                  "/api/v2/swagger.json"
        "/docs"             "/documentation"    "/redoc"
        "/rapidoc"          "/.well-known/openid-configuration"
        "/.well-known/jwks.json"
        # GraphQL
        "/graphql"          "/graphiql"         "/playground"
        "/api/graphql"      "/v1/graphql"       "/v2/graphql"
        "/query"            "/gql"
        # Auth
        "/auth"             "/auth/login"       "/auth/logout"
        "/auth/token"       "/auth/refresh"     "/auth/me"
        "/auth/register"    "/auth/verify"
        "/login"            "/logout"           "/register"
        "/signup"           "/signin"           "/signout"
        "/oauth"            "/oauth/token"      "/oauth/authorize"
        "/oauth/callback"   "/oauth2/token"     "/oauth2/authorize"
        "/token"            "/refresh"          "/refresh_token"
        "/api/login"        "/api/logout"       "/api/auth"
        "/api/auth/login"   "/api/auth/token"   "/api/token"
        "/api/refresh"      "/api/register"
        # CRUD genérico
        "/api/users"        "/api/user"         "/api/me"
        "/api/profile"      "/api/account"      "/api/accounts"
        "/api/admin"        "/api/roles"        "/api/permissions"
        "/api/groups"       "/api/members"
        "/api/products"     "/api/items"        "/api/catalog"
        "/api/categories"   "/api/orders"       "/api/cart"
        "/api/checkout"     "/api/payment"      "/api/payments"
        "/api/invoice"      "/api/billing"
        "/api/search"       "/api/query"        "/api/report"
        "/api/reports"      "/api/analytics"    "/api/stats"
        "/api/metrics"      "/api/events"       "/api/logs"
        "/api/audit"        "/api/notifications" "/api/messages"
        "/api/files"        "/api/upload"       "/api/download"
        "/api/export"       "/api/import"       "/api/sync"
        "/api/webhooks"     "/api/webhook"      "/api/callbacks"
        "/api/config"       "/api/settings"     "/api/preferences"
        "/api/status"       "/api/health"       "/api/ping"
        "/api/info"         "/api/version"      "/api/about"
        # Health / status
        "/health"           "/healthz"          "/health/live"
        "/health/ready"     "/health/check"
        "/status"           "/ping"             "/alive"
        "/ready"            "/readiness"        "/liveness"
        "/version"          "/info"
        # Spring Boot Actuator
        "/actuator"         "/actuator/health"  "/actuator/info"
        "/actuator/env"     "/actuator/beans"   "/actuator/metrics"
        "/actuator/mappings" "/actuator/loggers" "/actuator/heapdump"
        "/actuator/threaddump" "/actuator/shutdown"
        # WordPress REST
        "/wp-json"          "/wp-json/wp/v2"    "/wp-json/wp/v2/users"
        "/wp-json/wp/v2/posts" "/wp-json/wp/v2/pages"
        "/index.php?rest_route=/"
        # Debug / teste
        "/console"          "/debug"            "/trace"
        "/api/debug"        "/api/test"         "/api/dev"
        "/test"             "/demo"             "/sample"
    )

    local found_count=0
    {
        printf "\n  %-7s  %-60s\n" "STATUS" "ENDPOINT"
        printf "  %-7s  %-60s\n" \
            "───────" "────────────────────────────────────────────────────────────"
    } >> "$outfile"

    for path in "${API_PATHS[@]}"; do
        local sc
        sc=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 --max-time 10 \
            -H "Accept: application/json, */*" \
            -H "Content-Type: application/json" \
            -A "Mozilla/5.0" -L "${BASE}${path}" 2>/dev/null)

        if [[ "$sc" =~ ^(200|201|204|301|302|307|400|401|403|405|422|500)$ ]]; then
            printf "  %-7s  %s\n" "[$sc]" "$path" >> "$outfile"
            log_ok "[$sc] $path"
            ((found_count++))
        fi
    done

    echo "" >> "$outfile"

    # ── 2. GraphQL Introspection ──────────────────────────────
    log_info "Testando GraphQL introspection..."
    {
        echo "── GraphQL Introspection ───────────────────────────────────"
        echo ""
    } >> "$outfile"

    local GQL='{"query":"{ __schema { queryType { name } types { name kind fields { name } } } }"}'
    local gql_found=false
    for gp in "/graphql" "/api/graphql" "/graphiql" "/v1/graphql" "/v2/graphql" "/query" "/gql"; do
        local gr
        gr=$(curl -sk --connect-timeout 8 --max-time 15 \
            -X POST \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -d "$GQL" "${BASE}${gp}" 2>/dev/null)
        if echo "$gr" | grep -q '"__schema"' 2>/dev/null; then
            gql_found=true
            echo "  [VULNERÁVEL] Introspection HABILITADA: ${BASE}${gp}" >> "$outfile"
            log_warn "GraphQL introspection habilitada em ${gp}"
            {
                echo ""
                echo "  Tipos expostos:"
                echo "$gr" | jq -r '
                    .data.__schema.types[]
                    | select(.name | startswith("__") | not)
                    | "    \(.kind): \(.name)"
                ' 2>/dev/null | head -40
                echo ""
                echo "  Campos por tipo:"
                echo "$gr" | jq -r '
                    .data.__schema.types[]
                    | select(.name | startswith("__") | not)
                    | select(.fields != null)
                    | "    \(.name): \([.fields[].name] | join(", "))"
                ' 2>/dev/null | head -30
            } >> "$outfile"
            break
        fi
    done
    $gql_found || echo "  Introspection GraphQL não habilitada (ou não encontrado)." >> "$outfile"
    echo "" >> "$outfile"

    # ── 3. Parse de Swagger / OpenAPI ─────────────────────────
    log_info "Procurando spec OpenAPI/Swagger..."
    {
        echo "── Swagger / OpenAPI ───────────────────────────────────────"
        echo ""
    } >> "$outfile"

    local spec_found=false
    for spec in \
        "/swagger.json"             "/openapi.json" \
        "/swagger.yaml"             "/openapi.yaml" \
        "/api-docs"                 "/api-docs.json" \
        "/api/swagger.json"         "/api/openapi.json" \
        "/swagger/v1/swagger.json"  "/swagger/v2/swagger.json" \
        "/api/v1/swagger.json"      "/api/v2/swagger.json"; do

        local resp
        resp=$(_curl -H "Accept: application/json" "${BASE}${spec}" 2>/dev/null)
        if echo "$resp" | jq -e '(.paths // .info // .openapi // .swagger)' \
            &>/dev/null 2>&1; then
            spec_found=true
            local ep_count
            ep_count=$(echo "$resp" | jq -r '.paths | keys[]' 2>/dev/null | wc -l)
            {
                echo "  [ENCONTRADO] ${BASE}${spec}"
                echo "  Versão spec   : $(echo "$resp" | jq -r '.openapi // .swagger // "N/A"' 2>/dev/null)"
                echo "  Título        : $(echo "$resp" | jq -r '.info.title // "N/A"' 2>/dev/null)"
                echo "  Versão API    : $(echo "$resp" | jq -r '.info.version // "N/A"' 2>/dev/null)"
                echo "  Total endpoints: ${ep_count}"
                echo ""
                echo "  Endpoints:"
                echo "$resp" | jq -r '
                    .paths | to_entries[] |
                    .key as $p |
                    .value | to_entries[] |
                    "    [\(.key | ascii_upcase)] \($p)"
                ' 2>/dev/null | head -100
                echo ""
            } >> "$outfile"
            log_ok "Spec OpenAPI: ${spec} (${ep_count} endpoints)"
            break
        fi
    done
    $spec_found || echo "  Nenhum spec OpenAPI/Swagger encontrado." >> "$outfile"
    echo "" >> "$outfile"

    # ── 4. Subdomínios de API ─────────────────────────────────
    log_info "Verificando subdomínios de API (getent)..."
    {
        echo "── Subdomínios de API ──────────────────────────────────────"
        echo ""
    } >> "$outfile"

    local API_SUBS=(
        api api2 api3 rest graphql gateway apigw
        dev-api staging-api prod-api beta-api
        v1 v2 v3 backend service services
        microservice ms worker queue ws websocket
        grpc rpc public private internal sandbox test demo preview
    )
    for sub in "${API_SUBS[@]}"; do
        local fqdn="${sub}.${DOMAIN}"
        local ip
        ip=$(resolve_ip "$fqdn")
        if [ -n "$ip" ]; then
            local sc
            sc=$(_status "https://${fqdn}/")
            [ "$sc" == "000" ] && sc=$(_status "http://${fqdn}/")
            echo "  [${sc}] ${fqdn}  →  IP: ${ip}" >> "$outfile"
            log_ok "[$sc] ${fqdn} (${ip})"
        fi
    done
    echo "" >> "$outfile"

    # ── 5. CORS Misconfiguration ──────────────────────────────
    log_info "Verificando CORS..."
    {
        echo "── CORS ────────────────────────────────────────────────────"
        echo ""
    } >> "$outfile"

    local cors_h
    cors_h=$(curl -sk -I --connect-timeout 8 --max-time 12 \
        -H "Origin: https://evil.com" \
        -H "Access-Control-Request-Method: GET" \
        -X OPTIONS "${BASE}/api" 2>/dev/null)

    local acao acam acah acac
    acao=$(echo "$cors_h" | grep -i "Access-Control-Allow-Origin:"  | head -1)
    acam=$(echo "$cors_h" | grep -i "Access-Control-Allow-Methods:" | head -1)
    acah=$(echo "$cors_h" | grep -i "Access-Control-Allow-Headers:" | head -1)
    acac=$(echo "$cors_h" | grep -i "Access-Control-Allow-Credentials:" | head -1)

    if [ -n "$acao" ]; then
        echo "  $acao" >> "$outfile"
        [ -n "$acam" ] && echo "  $acam" >> "$outfile"
        [ -n "$acah" ] && echo "  $acah" >> "$outfile"
        [ -n "$acac" ] && echo "  $acac" >> "$outfile"
        echo "" >> "$outfile"
        if echo "$acao" | grep -q '\*'; then
            echo "  [AVISO] CORS aberto para qualquer origem (*)" >> "$outfile"
            log_warn "CORS wildcard (*) detectado"
        fi
        if echo "$acao" | grep -qi "evil\.com"; then
            echo "  [CRÍTICO] Origem evil.com refletida — CORS misconfiguration!" >> "$outfile"
            log_warn "CORS misconfiguration: evil.com refletido!"
        fi
    else
        echo "  CORS headers não encontrados em /api" >> "$outfile"
    fi

    {
        echo ""
        echo "── Resumo ──────────────────────────────────────────────────"
        echo "   Endpoints com resposta: ${found_count}"
        echo ""
    } >> "$outfile"

    log_ok "Concluído → ${outfile}"
    log_ok "Total: ${found_count} endpoints com resposta"
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
main() {
    check_deps
    show_banner

    # ── Coleta ordem dos serviços ──────────────────────────────
    echo -e "  ${BOLD}Digite a ordem dos serviços que deseja executar${RESET}"
    echo -e "  ${CYAN}Exemplo: 32514${RESET} → Portscan, Mapeamento, Subdomínios, Fingerprint, APIs"
    echo ""
    read -rp "  Ordem: " SERVICE_ORDER

    if [[ -z "$SERVICE_ORDER" ]]; then
        log_error "Nenhuma opção digitada. Encerrando."
        exit 1
    fi
    if ! [[ "$SERVICE_ORDER" =~ ^[1-5]+$ ]]; then
        log_error "Opções inválidas. Use apenas números de 1 a 5."
        exit 1
    fi

    # ── Coleta domínio ─────────────────────────────────────────
    echo ""
    read -rp "  Domínio principal a ser escaneado: " DOMAIN
    DOMAIN="${DOMAIN// /}"
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN%%/*}"

    if [[ -z "$DOMAIN" ]]; then
        log_error "Domínio não informado. Encerrando."
        exit 1
    fi

    # ── Cria pasta de saída: <dominio>MoreScan ─────────────────
    local folder_name="${DOMAIN}MoreScan"
    OUTPUT_DIR="${SCRIPT_DIR}/${folder_name}"
    mkdir -p "$OUTPUT_DIR"

    echo ""
    echo -e "${YELLOW}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "  Alvo    : ${BOLD}${DOMAIN}${RESET}"
    echo -e "  Serviços: ${BOLD}${SERVICE_ORDER}${RESET}"
    echo -e "  Saída   : ${BOLD}${OUTPUT_DIR}/${RESET}"
    echo -e "${YELLOW}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo ""

    export DOMAIN OUTPUT_DIR

    # ── Executa na ordem digitada ──────────────────────────────
    for (( i=0; i<${#SERVICE_ORDER}; i++ )); do
        local step="${SERVICE_ORDER:$i:1}"
        case "$step" in
            1) run_subdomain_enum ;;
            2) run_dir_mapping    ;;
            3) run_portscan       ;;
            4) run_fingerprint    ;;
            5) run_api_enum       ;;
        esac
    done

    echo ""
    echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  MoreScan finalizado!${RESET}"
    echo -e "${GREEN}${BOLD}  Resultados em: ${OUTPUT_DIR}/${RESET}"
    echo -e "${GREEN}${BOLD}  ══════════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

main "$@"
