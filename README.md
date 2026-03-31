# 🛡️ Linux Universal Hardening & SecOps Suite

Uma suíte de scripts automatizados para elevar a segurança (*hardening*) e auditar sistemas operacionais Linux. Desenvolvido com foco no conceito de **Defesa em Profundidade (Defense in Depth)**, este projeto configura camadas sobrepostas de segurança para proteger a máquina contra escalonamento de privilégios, vazamento de memória e ataques de rede.

**Sistemas Suportados Automaticamente:**
* Arch Linux (e derivados)
* Debian / Ubuntu
* Fedora / RHEL

---

## 📖 Filosofia de Segurança Aplicada

Em vez de apenas instalar antivírus ou procurar malwares, esta suíte altera o comportamento do núcleo do sistema operacional para torná-lo hostil a invasores. As principais proteções incluem:

1. **Mandatory Access Control (MAC):** Configura e força o uso de AppArmor (Arch/Debian) ou SELinux (Fedora) em modo *Enforcing*, contendo o "raio de explosão" de aplicações vulneráveis.
2. **Blindagem de Kernel (Sysctl):** Bloqueia *core dumps* (evitando vazamento de senhas da RAM se um programa travar), restringe acesso ao `dmesg`, bloqueia links simbólicos maliciosos e protege contra ataques de *side-channel*.
3. **Segurança de Rede:** Configura UFW ou Firewalld nativamente com política `DROP` (Deny) para entrada de dados. Ativa `log_martians` contra pacotes falsificados (*IP spoofing*).
4. **Governança de Sudo:** Limita tentativas de senha, diminui o *timeout* da sessão de root para 5 minutos, força o uso de TTY e ativa logs detalhados de auditoria em `/var/log/sudo.log`.

---

## 🎯 Cenários de Uso

* **Estações de Trabalho Pessoais (Endpoints):** Ideal para laptops de desenvolvedores e profissionais de TI que usam Linux no dia a dia (em cafés, aeroportos ou redes públicas) e precisam de uma máquina blindada contra explorações locais e ataques de rede.
* **Servidores Cloud (VPS / Bare Metal):** Excelente como um script de *post-install* ou *cloud-init* para novas instâncias na AWS, DigitalOcean ou Linode. Aplica uma *baseline* de segurança rigorosa antes de você expor serviços web (Nginx, Docker, etc.) para a internet.
* **Laboratórios de Cybersecurity:** Útil para estudantes de *Blue Team* estudarem como as configurações de Kernel e MAC interagem na prática.

---

## 🚀 Como Usar

O projeto é dividido em dois artefatos: o Escudo (que altera o sistema) e o Auditor (que verifica as falhas).

### Passo 1: Download
Clone este repositório para a sua máquina:
```bash
git clone [https://github.com/adalbertobrant/linux-universal-hardening.git](https://github.com/adalbertobrant/linux-universal-hardening.git)
cd linux-universal-hardening
chmod +x shield_universal.sh verify_universal.sh
```

### Passo 2: O Escudo (Hardening)
Execute o script de blindagem. **Aviso:** Este script fará alterações profundas no seu sistema, firewall e configurações de boot. Recomenda-se rodar em uma máquina recém-instalada ou fazer um backup prévio.

```bash
sudo ./shield_universal.sh
```
Após a conclusão com sucesso, **reinicie o sistema** para que as alterações de Kernel e bootloader (GRUB/systemd-boot) entrem em vigor:
```bash
sudo reboot
```

### Passo 3: O Auditor (Verificação)
Após o reboot, execute o script de verificação para auditar a postura de segurança atual do sistema. Ele testará cada parâmetro e gerará um *score* de 0 a 100%.

```bash
./verify_universal.sh
```
Se o sistema atingir 100%, sua máquina está blindada. Se houver falhas, o relatório apontará exatamente qual camada de segurança precisa de atenção manual.

---

## 🤝 Contribuições

Contribuições são bem-vindas! Se você deseja adicionar suporte a outras distribuições (como Alpine ou SUSE), melhorar as políticas de *sysctl* ou implementar a versão avançada com logs em banco de dados SQLite3, sinta-se à vontade para abrir uma *Issue* ou enviar um *Pull Request*.

## 📄 Licença

Este projeto é open-source. Use com responsabilidade e audite os scripts antes de rodá-los em ambientes de produção.
```
