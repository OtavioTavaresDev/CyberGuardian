CyberGuardian - Suíte de Cibersegurança em Python
Sobre o Projeto
CyberGuardian é uma aplicação educacional desenvolvida em Python que reúne múltiplas ferramentas de cibersegurança em uma interface gráfica amigável. Projetado para estudantes, entusiastas e profissionais iniciantes em segurança da informação, o projeto combina funcionalidades práticas com explicações detalhadas para facilitar o aprendizado.

Características Principais
Interface gráfica moderna e intuitiva

Múltiplas ferramentas em uma única aplicação

Resultados detalhados e explicativos

Processamento assíncrono para operações de rede

Design com código de cores para diferentes níveis de severidade

Totalmente desenvolvido em Python

Funcionalidades
1. Scanner de Portas
Escaneamento de portas TCP em hosts específicos

Identificação automática de serviços

Intervalo de portas personalizável

Relatório detalhado de portas abertas/fechadas

2. Analisador de Senhas
Avaliação da força de senhas

Verificação contra senhas comuns

Pontuação detalhada com feedback

Sugestões para melhorar a segurança

3. Monitor de Logs
Análise de arquivos de log em tempo real

Detecção de atividades suspeitas

Classificação por níveis (INFO, WARNING, ERROR, CRITICAL)

Resumo estatístico da análise

4. Verificador de Links
Análise de URLs por características suspeitas

Verificação de protocolos de segurança (HTTP/HTTPS)

Detecção de redirecionamentos

Verificação de cabeçalhos de segurança

5. Ferramenta de Criptografia
Criptografia/Descriptografia de texto

Geração de múltiplos tipos de hash

Suporte a chaves personalizadas

Algoritmos suportados: Base64 + XOR, MD5, SHA-1, SHA-256, SHA-512

Pré-requisitos
Python 3.8 ou superior

Sistema operacional: Windows, Linux ou macOS

Conexão com a internet (apenas para a função de verificação de URLs)

Instalação
Método 1: Instalação Básica
Baixe o arquivo cyberguardian.py

Instale as dependências necessárias:

text
pip install requests
Execute o aplicativo:

text
python cyberguardian.py
Método 2: Usando Ambiente Virtual (Recomendado)
text
# Criar ambiente virtual
python -m venv venv

# Ativar ambiente virtual
# No Windows:
venv\Scripts\activate
# No Linux/macOS:
source venv/bin/activate

# Instalar dependências
pip install requests

# Executar aplicativo
python cyberguardian.py
Como Usar
Interface Principal
O aplicativo é dividido em 5 abas principais, cada uma correspondendo a uma ferramenta específica.

1. Scanner de Portas
Na aba "Scanner de Portas"

Digite o host ou IP (ex: localhost, 192.168.1.1)

Defina o intervalo de portas (ex: 1-1024)

Clique em "Iniciar Scanner"

Aguarde os resultados na área de texto

2. Analisador de Senhas
Na aba "Analisador de Senhas"

Digite a senha para análise (ela será mascarada)

Clique em "Analisar Senha"

Veja a pontuação e recomendações

3. Monitor de Logs
Na aba "Monitor de Logs"

Digite o caminho do arquivo de log (ex: ./exemplo.log)

Clique em "Analisar Logs"

Revise as atividades detectadas e alertas

4. Verificador de Links
Na aba "Verificador de Links"

Digite a URL completa (ex: https://exemplo.com)

Clique em "Verificar URL"

Analise os resultados de segurança

5. Ferramenta de Criptografia
Na aba "Criptografia"

Digite o texto na área superior

(Opcional) Defina uma chave

Clique no botão desejado:

Criptografar: Para criptografar o texto

Descriptografar: Para descriptografar texto criptografado

Gerar Hash: Para criar hashes do texto 

Avisos Importantes
Para Fins Educacionais
Este aplicativo é desenvolvido exclusivamente para fins educacionais e de aprendizado. Não deve ser utilizado para:

Testar sistemas sem autorização explícita

Realizar ataques a sistemas de terceiros

Violar leis locais de cibersegurança

Substituir ferramentas profissionais de segurança

Considerações de Segurança
A criptografia implementada é básica e não deve ser usada para proteger dados sensíveis

O scanner de portas pode ser detectado por sistemas de segurança

Sempre obtenha permissão antes de testar em sistemas que não são seus

Este software é fornecido "COMO ESTÁ" sem garantias

Boas Práticas de Segurança
Para Senhas:
Use pelo menos 12 caracteres

Combine letras, números e símbolos

Não reutilize senhas entre serviços

Considere usar um gerenciador de senhas

Para Sistemas:
Mantenha software atualizado

Use firewall ativo

Monitore logs regularmente

Implemente autenticação de dois fatores

Para Navegação:
Verifique sempre se sites usam HTTPS

Desconfie de links encurtados

Não baixe arquivos de fontes desconhecidas

Use extensões de segurança no navegador

Solução de Problemas
Problema: Erro ao instalar dependências
Solução:

text
# Atualize o pip
pip install --upgrade pip

# Tente instalar novamente
pip install requests
Problema: Interface não carrega
Solução:

Verifique se você tem Python 3.8 ou superior

Execute como administrador se necessário

Verifique se há conflitos com outros programas

Problema: Scanner de portas não funciona
Solução:

Verifique sua conexão de rede

Certifique-se de ter permissões suficientes

Teste com localhost primeiro

Problema: Verificador de links retorna erro
Solução:

Verifique sua conexão com a internet

Certifique-se de que a URL está completa

Tente uma URL diferente para teste

Roadmap e Melhorias Futuras
Melhorias Planejadas:
Scanner de vulnerabilidades em sites

Analisador de pacotes de rede

Verificador de metadados de arquivos

Detector de phishing avançado

Integração com APIs de segurança

Relatórios em PDF/HTML

Sistema de plugins

Funcionalidades em Desenvolvimento:
Exportação de resultados

Histórico de análises

Templates de relatórios

Modo linha de comando

Contribuições
Contribuições são bem-vindas! Para contribuir:

Faça um fork do projeto

Crie uma branch para sua feature

Commit suas mudanças

Push para a branch

Abra um Pull Request

Áreas que Precisam de Ajuda:
Traduções para outros idiomas

Testes unitários adicionais

Documentação expandida

Melhorias na interface gráfica

Novas ferramentas e funcionalidades

Licença
Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

Resumo da Licença:
Uso comercial permitido

Modificação e distribuição permitidas

Uso em projetos privados permitido

Sub-licenciamento permitido

Sem garantias de qualquer tipo

Aviso de Uso Ético:
Este software é fornecido apenas para fins educacionais, de aprendizado e teste autorizado em sistemas próprios. É responsabilidade do usuário obter permissão explícita antes de testar qualquer sistema de terceiros e obedecer todas as leis aplicáveis. O autor não se responsabiliza por qualquer uso indevido ou dano causado por este programa.

Suporte e Contato
Para suporte, reporte de bugs ou sugestões:

Reportar problemas: Através da página do projeto

Reconhecimentos
Desenvolvido com Python e Tkinter

Inspirado em ferramentas de segurança open-source

Comunidade de cibersegurança

Python Software Foundation

Aviso Legal Final
Use este software apenas em sistemas que você possui ou tem permissão explícita para testar. O desenvolvedor não se responsabiliza por uso indevido ou ilegal desta ferramenta.

Segurança Responsável: A cibersegurança é uma responsabilidade compartilhada. Use seu conhecimento para proteger, não para prejudicar.
