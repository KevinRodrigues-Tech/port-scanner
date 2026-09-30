# 🛡️ TCP Port Scanner

Uma ferramenta de linha de comando (CLI) desenvolvida em Python para escaneamento rápido de portas TCP e identificação de serviços (banner grabbing). Focada em performance e simplicidade, utiliza **apenas bibliotecas nativas**, tornando-a ideal para ambientes controlados, laboratórios de cibersegurança e auditorias ágeis de infraestrutura sem a necessidade de instalar dependências complexas.

---

## ✨ Funcionalidades

* 🚀 **Multithreading de Alta Performance:** Escaneamento concorrente (`ThreadPoolExecutor`) que reduz o tempo de varredura de milhares de portas para poucos segundos.
* 🧠 **Banner Grabbing Inteligente:** Identifica automaticamente os serviços em execução e tenta capturar as assinaturas reais da aplicação (ex: `SSH-2.0-OpenSSH`).
* 📦 **Zero Dependências (Built-in):** Construído 100% com a biblioteca padrão do Python. Funciona "out-of-the-box" em qualquer máquina com Python instalado.
* 💾 **Exportação Profissional:** Capacidade de gerar relatórios estruturados em formato `.json` ou texto simples (`.txt`) para documentação de auditorias.
* 🛡️ **Resiliência:** Tratamento robusto de erros contra timeouts, falhas de resolução de DNS e interrupções abruptas do usuário.

---

## ⚙️ Pré-requisitos e Instalação

Requer apenas **Python 3.7 ou superior**. Nenhuma instalação via `pip` é necessária.

```bash
# Clone o repositório
git clone [https://github.com/SEU-USUARIO/tcp-port-scanner.git](https://github.com/SEU-USUARIO/tcp-port-scanner.git)

# Acesse o diretório
cd tcp-port-scanner

# Execute o scanner
python scanner.py --help
```

---

## 🛠️ Como Utilizar (Uso)

O scanner é operado via linha de comando. A sintaxe básica é:
`python scanner.py -t <ALVO> [OPÇÕES]`

### Tabela de Argumentos

| Flag | Nome Extenso | Descrição | Exemplo |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | **(Obrigatório)** IP ou Hostname alvo. | `-t 192.168.1.1` ou `-t scanme.nmap.org` |
| `-p` | `--ports` | Portas a escanear (única, lista ou range). Padrão: 1-1024 | `-p 80` ou `-p 22,80,443` ou `-p 1-5000` |
| `-T` | `--threads` | Quantidade de threads simultâneas. Padrão: 100 | `-T 200` |
| `-o` | `--output` | Exporta os resultados para um arquivo. | `-o relatorio.json` ou `-o log.txt` |

---

## 💡 Exemplos Práticos

**1. Scan Básico (Portas Padrão)**
Inicia um scan nas portas de 1 a 1024 usando 100 threads no localhost.
```bash
python scanner.py -t 127.0.0.1
```

**2. Scan Rápido e Agressivo (Todas as Portas)**
Varre todas as 65.535 portas do TCP em um servidor de laboratório utilizando 500 threads para velocidade máxima.
```bash
python scanner.py -t 192.168.0.15 -p 1-65535 -T 500
```

**3. Scan Direcionado com Exportação JSON**
Verifica portas específicas de infraestrutura web e salva o resultado detalhado em um arquivo JSON.
```bash
python scanner.py -t 10.0.0.5 -p 22,80,443,8080,3306 -o relatorio_web.json
```

---

## 🎯 Onde Utilizar?

Este projeto foi desenhado para cenários práticos do dia a dia de profissionais de TI e Cibersegurança:

* **Laboratórios e CTFs (Offensive Security):** Reconhecimento inicial ultra-rápido em plataformas como Hack The Box ou TryHackMe, sem o "ruído" e a demora de escaneamentos completos de outras ferramentas.
* **Hardening e Defesa (Purple Team):** Mapeamento do seu próprio host (ex: distribuições Linux, servidores de desenvolvimento) para garantir que nenhum serviço indesejado esteja exposto.
* **Troubleshooting de IoT:** Validação rápida de conectividade e status de portas em dispositivos de hardware como Raspberry Pi ou Jetson Nano.
* **Auditorias Iniciais:** Levantamento ágil de superfície de ataque em infraestruturas recém-configuradas, com fácil geração de relatórios JSON para documentação.

---

## ⚠️ Aviso Legal

Esta é uma ferramenta voltada para **estudos, laboratórios de segurança e testes autorizados**. O uso deste software para escaneamento de redes, servidores ou sistemas de terceiros sem o consentimento prévio, explícito e formal dos proprietários é estritamente proibido. O desenvolvedor não se responsabiliza pelo uso indevido da ferramenta.

---

## 📄 Licença

Este projeto está sob a licença **MIT** - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
