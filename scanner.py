#!/usr/bin/env python3
"""
Scanner de Portas TCP - Fase 4
Um scanner de portas TCP profissional com multithreading, identificação de serviços,
banner grabbing e exportação de relatórios.
"""

import argparse
import concurrent.futures
import socket
import sys
import time
from typing import List, Optional, Tuple


# Dicionário de mapeamento de portas comuns para serviços
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    631: "IPP/CUPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}


def _process_banner_data(data: bytes) -> str:
    """
    Processa os dados brutos recebidos em um banner.

    Args:
        data: Dados brutos recebidos do socket

    Returns:
        String processada do banner (máx 60 chars, sem quebras de linha)
    """
    try:
        # Decodifica bytes para string, ignorando erros de decodificação
        banner_str = data.decode('utf-8', errors='ignore')
        # Remove caracteres de quebra de linha
        banner_str = banner_str.replace('\r', '').replace('\n', ' ')
        # Remove espaços extras e limita a 60 caracteres
        banner_str = ' '.join(banner_str.split())[:60]
        return banner_str if banner_str else "Nenhum banner capturado"
    except Exception:
        return "Nenhum banner capturado"


def _print_ascii_banner() -> None:
    """Imprime um banner ASCII simples no início da execução."""
    banner = """
    ███╗   ███╗ █████╗ ███╗   ██╗███████╗██████╗ ███╗   ███╗███████╗
    ████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝
    ██╔████╔██║███████║██╔██╗ ██║█████╗  ██████╔╝██╔████╔██║███████╗
    ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔════╝
    ██║ ╚═╝ ██║██║  ██║██║ ╚████║███████╗██║  ██║██║ ╚═╝ ██║███████╗
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
    """
    print(banner)


def parse_ports(port_string: str) -> List[int]:
    """
    Converte uma string de portas em uma lista de inteiros.

    Suporta três formatos:
    - Porta única: "80"
    - Lista separada por vírgula: "22,80,443"
    - Range de portas: "1-100" (inclusivo)

    Args:
        port_string: String representando as portas a serem escaneadas

    Returns:
        Lista de inteiros representando as portas

    Raises:
        ValueError: Se o formato da string de portas for inválido ou se as portas estiverem fora do intervalo válido (1-65535)
    """
    ports = []

    # Divide por vírgula para tratar listas
    parts = port_string.split(',')

    for part in parts:
        part = part.strip()

        # Verifica se é um range (contém hífen)
        if '-' in part:
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())

                if start_port > end_port:
                    raise ValueError(f"Range inválido: {start_port}-{end_port}")

                # Valida se as portas estão no intervalo válido
                if start_port < 1 or start_port > 65535:
                    raise ValueError(f"Porta de início inválida: {start_port}. Deve estar entre 1 e 65535")
                if end_port < 1 or end_port > 65535:
                    raise ValueError(f"Porta de fim inválida: {end_port}. Deve estar entre 1 e 65535")

                # Adiciona todas as portas no range (inclusivo)
                ports.extend(range(start_port, end_port + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Portas inválidas no range: {part}")
                else:
                    raise e
        else:
            # Porta única
            try:
                port = int(part)
                # Valida se a porta está no intervalo válido
                if port < 1 or port > 65535:
                    raise ValueError(f"Porta inválida: {port}. Deve estar entre 1 e 65535")
                ports.append(port)
            except ValueError as e:
                if "invalid literal" in str(e) or "Deve estar entre" in str(e):
                    raise e
                else:
                    raise ValueError(f"Porta inválida: {part}")

    # Remove duplicatas e ordena
    return sorted(list(set(ports)))


def scan_port(ip: str, port: int) -> Optional[Tuple[str, str]]:
    """
    Verifica se uma porta específica está aberta em um endereço IP e tenta capturar o banner.

    Args:
        ip: Endereço IP alvo
        port: Número da porta a ser verificada

    Returns:
        None se a porta estiver fechada/filtered.
        Tupla (servico, banner) se a porta estiver aberta, onde:
        - servico: nome do serviço do COMMON_PORTS ou "Desconhecido"
        - banner: string do banner capturado (máx 60 chars) ou "Nenhum banner capturado"
    """
    sock = None
    try:
        # Cria socket IPv4 TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Define timeout curto para evitar travamento na conexão
        sock.settimeout(1.0)
        # Tenta conectar
        result = sock.connect_ex((ip, port))
        # connect_ex retorna 0 se a conexão tiver sucesso
        if result != 0:
            return None  # Porta fechada ou filtrada

        # Porta aberta, tenta identificar serviço e capturar banner
        service = COMMON_PORTS.get(port, "Desconhecido")
        banner = "Nenhum banner capturado"

        try:
            # Timeout baixo para receber banner (não prender a thread)
            sock.settimeout(1.0)
            # Primeira tentativa de receber dados
            data = sock.recv(1024)
            if data:
                banner = _process_banner_data(data)
            else:
                # Segunda tentativa: enviar requisição genérica e tentar novamente
                # Alguns serviços (como HTTP) não falam nada até o cliente enviar uma requisição
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    banner = _process_banner_data(data)
        except (socket.timeout, socket.error):
            # Mantém o banner padrão se houver erro na captura (falha silenciosa)
            pass

        return (service, banner)
    except socket.error:
        # Qualquer erro de socket indica porta fechada/filtered
        return None
    finally:
        # Garante que o socket seja fechado
        if sock:
            sock.close()


def main() -> None:
    """Função principal do scanner de portas."""
    # Imprime o banner ASCII
    _print_ascii_banner()

    # Configura o parser de argumentos
    parser = argparse.ArgumentParser(
        description="Scanner de Portas TCP - Fase 4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python scanner.py -t 192.168.1.1
  python scanner.py -t scanme.nmap.org -p 80,443
  python scanner.py -t 127.0.0.1 -p 1-1000 -T 200 -o resultado.json
        """
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Endereço IP ou hostname alvo (ex: 192.168.1.1 ou scanme.nmap.org)'
    )

    parser.add_argument(
        '-p', '--ports',
        default='1-1024',
        help='Portas a serem escaneadas (padrão: 1-1024). Formatos suportados: 80, 22,80,443, 1-100'
    )

    parser.add_argument(
        '-T', '--threads',
        type=int,
        default=100,
        help='Número máximo de threads simultâneas (padrão: 100)'
    )

    parser.add_argument(
        '-o', '--output',
        help='Arquivo para salvar os resultados (ex: resultado.json ou scan_relatorio.txt)'
    )

    args = parser.parse_args()

    try:
        # Resolve o hostname para IP
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Erro: Não foi possível resolver o hostname '{args.target}'")
        sys.exit(1)

    try:
        # Processa o argumento de portas
        port_list = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Erro: {e}")
        sys.exit(1)

    # Cabeçalho do scan
    print(f"[*] Iniciando scan em {target_ip}...")
    print(f"[*] Escaneando {len(port_list)} porta(s) com {args.threads} thread(s)")

    # Lista para armazenar os resultados das portas abertas
    open_ports_results = []

    # Captura o tempo inicial
    start_time = time.time()

    try:
        # Implementação de concorrência com ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Mapeia a função scan_port para cada porta na lista
            future_to_port = {executor.submit(scan_port, target_ip, port): port for port in port_list}

            # Processa os resultados conforme eles são concluídos
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result is not None:
                        service, banner = result
                        result_dict = {'porta': port, 'servico': service, 'banner': banner}
                        open_ports_results.append(result_dict)
                        print(f"[+] Porta {port} ABERTA | Serviço: {service} | Banner: {banner}")
                except Exception as e:
                    # Trata exceções individuais de portas silenciosamente para não sujar o output
                    pass  # Ignora erros individuais para manter a saída limpa
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Erro inesperado durante o scan: {e}")
        sys.exit(1)

    # Calcula e exibe o tempo total
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"[*] Scan concluído em {elapsed_time:.2f} segundos")

    # Exporta os resultados se o argumento --output foi fornecido
    if args.output:
        try:
            if args.output.endswith('.json'):
                import json
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(open_ports_results, f, indent=4, ensure_ascii=False)
            else:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for result in open_ports_results:
                        f.write(f"Porta: {result['porta']}, Serviço: {result['servico']}, Banner: {result['banner']}\n")
            print(f"[*] Resultados salvos em: {args.output}")
        except Exception as e:
            print(f"[!] Erro ao salvar resultados: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()