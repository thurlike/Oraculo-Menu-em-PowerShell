Oráculo Menu em PowerShell

O Oráculo Menu em PowerShell é uma solução desenvolvida para centralizar, organizar e padronizar tarefas administrativas em ambientes Windows. Ele foi criado para apoiar profissionais de suporte, infraestrutura e operações de TI que precisam executar rotinas técnicas com agilidade, segurança e consistência, sem depender de múltiplas ferramentas ou comandos isolados.

O funcionamento é baseado em um menu interativo em modo console. Ao executar o script, o usuário é apresentado a uma interface estruturada com categorias como sistema, usuários, processos e serviços, rede, disco e arquivos, auditoria de logs, backup, otimização do sistema e, quando disponíveis no ambiente, módulos avançados como Active Directory e Hyper-V. Cada opção do menu chama funções internas específicas, com validações, tratamento de erros e mensagens claras de retorno.

O Oráculo não substitui boas práticas administrativas, mas atua como um acelerador operacional, reduzindo tempo de atendimento, padronizando procedimentos e diminuindo falhas humanas. Ele também foi pensado com foco em governança, permitindo evoluções como controle de permissões, auditoria de ações e assinatura de código para garantir integridade do script.

Como executar

Salve o arquivo do projeto (ex: Oraculo.ps1) em seu computador.

Abra o PowerShell.

Caso necessário, permita a execução temporária:

powershell -ExecutionPolicy Bypass -File .\Oraculo.ps1


ou ajuste a política para seu usuário:

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser


Execute o script e navegue pelo menu interativo.

O projeto é aberto à comunidade, extensível e pensado para evolução contínua, incentivando automação responsável, compartilhamento de conhecimento e operações de TI mais eficientes, seguras e bem estruturadas.
