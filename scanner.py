#!/usr/bin/env python3
"""
Network Port Scanner
Ferramenta de varredura de portas com SYN scan e banner grabbing.
Autor: Gabriel Vieira
"""

import argparse
import socket
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# --- Cores para terminal ---
class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# --- Serviços conhecidos por porta ---
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  _____           _     _____                                 
 |  __ \\         | |   / ____|                                
 | |__) |__  _ __| |_ | (___   ___ __ _ _ __  _ __   ___ _ __
 |  ___/ _ \\| '__| __| \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |  | (_) | |  | |_  ____) | (_| (_| | | | | | | |  __/ |   
 |_|   \\___/|_|   \\__||_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
{Colors.RESET}
{Colors.YELLOW}  Network Port Scanner — by Gabriel Vieira{Colors.RESET}
    """
    print(banner)


def resolve_host(target: str) -> str:
    """Resolve hostname para IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"{Colors.RED}[ERRO] Não foi possível resolver o host: {target}{Colors.RESET}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Tenta capturar o banner do serviço via socket TCP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Envia requisição básica para forçar resposta
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            # Retorna só a primeira linha relevante
            first_line = banner.split("\n")[0][:80]
            return first_line if first_line else ""
    except Exception:
        return ""


def syn_scan(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Realiza SYN scan usando Scapy.
    Envia pacote SYN e verifica se recebe SYN-ACK (porta aberta).
    Requer privilégios de root/admin.
    """
    conf.verb = 0  # Silencia output do Scapy
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # Envia RST para fechar conexão corretamente
            rst = IP(dst=ip) / TCP(dport=port, flags="R")
            sr1(rst, timeout=0.5)
            return True
    return False


def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    TCP Connect scan — fallback quando Scapy não está disponível
    ou sem privilégios root.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def scan_port(ip: str, port: int, use_syn: bool, timeout: float, grab: bool) -> dict:
    """Varre uma porta e retorna resultado."""
    if use_syn and SCAPY_AVAILABLE:
        is_open = syn_scan(ip, port, timeout)
    else:
        is_open = tcp_connect_scan(ip, port, timeout)

    result = {
        "port": port,
        "open": is_open,
        "service": KNOWN_SERVICES.get(port, "Desconhecido"),
        "banner": "",
    }

    if is_open and grab:
        result["banner"] = grab_banner(ip, port, timeout)

    return result


def parse_ports(port_arg: str) -> list:
    """
    Interpreta argumento de portas:
    - '80'         → [80]
    - '80,443,22'  → [80, 443, 22]
    - '1-1024'     → [1, 2, ..., 1024]
    - 'common'     → portas mais comuns
    """
    if port_arg == "common":
        return list(KNOWN_SERVICES.keys())

    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def save_report(target: str, ip: str, results: list, output_file: str):
    """Salva relatório em arquivo .txt."""
    open_ports = [r for r in results if r["open"]]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("       RELATÓRIO DE VARREDURA DE PORTAS\n")
        f.write("=" * 60 + "\n")
        f.write(f"Alvo     : {target} ({ip})\n")
        f.write(f"Data/Hora: {timestamp}\n")
        f.write(f"Portas abertas encontradas: {len(open_ports)}\n")
        f.write("=" * 60 + "\n\n")

        if open_ports:
            f.write(f"{'PORTA':<10} {'SERVIÇO':<20} {'BANNER'}\n")
            f.write("-" * 60 + "\n")
            for r in open_ports:
                f.write(f"{r['port']:<10} {r['service']:<20} {r['banner']}\n")
        else:
            f.write("Nenhuma porta aberta encontrada.\n")

    print(f"\n{Colors.CYAN}[*] Relatório salvo em: {output_file}{Colors.RESET}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Network Port Scanner com SYN scan e banner grabbing"
    )
    parser.add_argument("target", help="IP ou hostname do alvo")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Portas: '80', '1-1024', '80,443,22', 'common' (padrão: common)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float, default=1.0,
        help="Timeout por porta em segundos (padrão: 1.0)"
    )
    parser.add_argument(
        "-T", "--threads",
        type=int, default=100,
        help="Número de threads paralelas (padrão: 100)"
    )
    parser.add_argument(
        "--syn",
        action="store_true",
        help="Usar SYN scan via Scapy (requer root)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Desativar banner grabbing"
    )
    parser.add_argument(
        "-o", "--output",
        help="Salvar relatório em arquivo (ex: resultado.txt)"
    )

    args = parser.parse_args()

    # Resolve host
    ip = resolve_host(args.target)
    ports = parse_ports(args.ports)
    grab = not args.no_banner

    # Aviso de modo
    if args.syn and not SCAPY_AVAILABLE:
        print(f"{Colors.YELLOW}[!] Scapy não encontrado. Usando TCP Connect scan.{Colors.RESET}")
    elif args.syn:
        print(f"{Colors.CYAN}[*] Modo: SYN Scan (Scapy){Colors.RESET}")
    else:
        print(f"{Colors.CYAN}[*] Modo: TCP Connect Scan{Colors.RESET}")

    print(f"{Colors.CYAN}[*] Alvo : {args.target} ({ip}){Colors.RESET}")
    print(f"{Colors.CYAN}[*] Portas: {len(ports)} porta(s) para varrer{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads} | Timeout: {args.timeout}s{Colors.RESET}")
    print("-" * 50)

    results = []
    open_count = 0

    # Varredura paralela com ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.syn, args.timeout, grab): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result["open"]:
                open_count += 1
                service = result["service"]
                banner = f" — {result['banner']}" if result["banner"] else ""
                print(
                    f"{Colors.GREEN}[ABERTA]{Colors.RESET} "
                    f"Porta {Colors.BOLD}{result['port']}/tcp{Colors.RESET} "
                    f"({Colors.YELLOW}{service}{Colors.RESET}){banner}"
                )

    # Resumo final
    print("-" * 50)
    print(f"\n{Colors.BOLD}Varredura concluída.{Colors.RESET} "
          f"{Colors.GREEN}{open_count} porta(s) aberta(s){Colors.RESET} "
          f"de {len(ports)} verificada(s).")

    # Salvar relatório
    if args.output:
        results.sort(key=lambda x: x["port"])
        save_report(args.target, ip, results, args.output)


if __name__ == "__main__":
    main()
