# Finanças

## Dependencias: 
Instalar o Docker:
- [Windows](https://docs.docker.com/desktop/setup/install/windows-install/)
- [Linux](https://docs.docker.com/desktop/setup/install/linux-install/)
- [Mac](https://orbstack.dev/download)

Instalar o Git:
- [Windows](https://git-scm.com/install/)

Inicie o Docker.

## Clonar o código

- Execute no seu terminal
```bash
git clone https://github.com/rasj/deolho.git
```

ou 

- Acesse [https://github.com/rasj/deolho.git](https://github.com/rasj/deolho.git)

- Clique em `Code`

- Clique em `Download ZIP`

## Ambiente
- Vá para a pasta onde o código foi baixado.

- Copie e cope o arquivo backend/.env-sample para backend/.env.

- Preencha os dados no arquivo backend/.env com dados aleatorios.

## Iniciar

- Vá para a pasta onde o código foi baixado.

Mac / Linux:
```bash 
docker compose up -d
```

Windows: 
- Vá pelo Explorer até a pasta do projeto.
- Aperte a tecla "Shift" e clique com o botão direito do mouse na pasta.
- Selecione "Abrir janela do PowerShell aqui"
- Digite: 
```powershell
docker compose up -d
```

O programa está configurado para continuar rodando sempre que o Docker estiver ativo. Se deseja desativar o serviço manualmente você pode rodar o comando abaixo:

```bash
docker compose down
```

## Backup

### Postgress
```bash
source .env
docker exec finances-postgres pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB_AUTH} > backup.sql
```

### Sqlite
Seus bancos de dados ficam na pasta: `backend/data/`, basta copiar estes arquivos para fazer o backup.

## Atualizações:
- Vá para a pasta onde o código foi baixado.

- Execute no terminal:
```bash 
git pull
```


## Acessando:
- Acesse: https://local.deolho.com
- Crie sua Conta
- Crie sua Organização
- Crie seu Banco de Dados.
- Crie suas Contas Bancarias
- Importe seus Extratos
- Organize seus vinculos
- Configure suas automações baseado nos padrões de dados identificados no seu extrato. (Crie categorias, tags, vinculos, etc)
- Rode suas automações
- Proteja dados sensiveis com a ferramenta de Auto-Redacted.
- Mescle vinculos que possuem identificadores diferentes mas são a mesma entidade.
- Converta transações entre contas de debito/credito para "Transferencia de saida" ou "Transferencia de entrada". (Voce pode fazer uma automação para isto.)
- Faça sua conciliação financeira.
- Veja os relatorios.
- Informe seus Investimentos, Criptoativos, etc.
- Acompanhe seus gastos e receitas.
- Gere um relátorio mensal em PDF.

