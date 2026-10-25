import sqlite3


def conectar_banco():
    conexao = sqlite3.connect('database.db')
    conexao.row_factory = sqlite3.Row
    return conexao


def criar_tabelas():
    conexao = conectar_banco()
    try:
        cursor = conexao.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                senha TEXT NOT NULL,
                perfil TEXT NOT NULL DEFAULT 'solicitante'
            )
        ''')
        colunas_usuarios = {c['name'] for c in cursor.execute('PRAGMA table_info(usuarios)')}
        if 'perfil' not in colunas_usuarios:
            cursor.execute("ALTER TABLE usuarios ADD COLUMN perfil TEXT NOT NULL DEFAULT 'solicitante'")

        # Mantida somente para compatibilidade com os pedidos antigos.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ferramentas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE
            )
        ''')
        ferramentas = [
            'Molde de injeção convencional', 'Molde de sopro',
            'Molde de borracha', 'Molde de rotomoldagem',
            'Molde de termoformagem', 'Ferramentas de Fundição',
            'Dispositivos', 'Outros'
        ]
        cursor.executemany(
            'INSERT OR IGNORE INTO ferramentas (nome) VALUES (?)',
            [(nome,) for nome in ferramentas]
        )

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pedidos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                solicitante TEXT NOT NULL,
                ferramenta_id INTEGER,
                prazo TEXT NOT NULL,
                status TEXT NOT NULL,
                abertura TEXT NOT NULL,
                atendido TEXT,
                feedback TEXT,
                descricao TEXT,
                excluido INTEGER NOT NULL DEFAULT 0,
                usuario_id INTEGER REFERENCES usuarios(id),
                descricao_solicitante TEXT,
                descricao_ferramentaria TEXT,
                FOREIGN KEY (ferramenta_id) REFERENCES ferramentas(id)
            )
        ''')
        info = list(cursor.execute('PRAGMA table_info(pedidos)'))
        nomes = {c['name'] for c in info}

        # Atualizações de bases já existentes. Preservamos a autoria desconhecida
        # dos pedidos antigos, sem associá-los a qualquer usuário por suposição.
        for coluna, definicao in [
            ('excluido', 'INTEGER NOT NULL DEFAULT 0'),
            ('usuario_id', 'INTEGER REFERENCES usuarios(id)'),
            ('descricao_solicitante', 'TEXT'),
            ('descricao_ferramentaria', 'TEXT'),
        ]:
            if coluna not in nomes:
                cursor.execute(f'ALTER TABLE pedidos ADD COLUMN {coluna} {definicao}')

        info = list(cursor.execute('PRAGMA table_info(pedidos)'))
        ferramenta_obrigatoria = any(
            c['name'] == 'ferramenta_id' and c['notnull'] == 1 for c in info
        )
        if ferramenta_obrigatoria:
            # SQLite não permite retirar NOT NULL com ALTER COLUMN.
            # Recriamos somente esta tabela dentro de uma transação, copiando
            # todos os registros e IDs, inclusive os excluídos logicamente.
            cursor.execute('''
                CREATE TABLE pedidos_novos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data TEXT NOT NULL,
                    solicitante TEXT NOT NULL,
                    ferramenta_id INTEGER,
                    prazo TEXT NOT NULL,
                    status TEXT NOT NULL,
                    abertura TEXT NOT NULL,
                    atendido TEXT,
                    feedback TEXT,
                    descricao TEXT,
                    excluido INTEGER NOT NULL DEFAULT 0,
                    usuario_id INTEGER REFERENCES usuarios(id),
                    descricao_solicitante TEXT,
                    descricao_ferramentaria TEXT,
                    FOREIGN KEY (ferramenta_id) REFERENCES ferramentas(id)
                )
            ''')
            cursor.execute('''
                INSERT INTO pedidos_novos (
                    id, data, solicitante, ferramenta_id, prazo, status,
                    abertura, atendido, feedback, descricao, excluido,
                    usuario_id, descricao_solicitante, descricao_ferramentaria
                )
                SELECT id, data, solicitante, ferramenta_id, prazo, status,
                    abertura, atendido, feedback, descricao, excluido,
                    usuario_id, descricao_solicitante, descricao_ferramentaria
                FROM pedidos
            ''')
            cursor.execute('DROP TABLE pedidos')
            cursor.execute('ALTER TABLE pedidos_novos RENAME TO pedidos')

        # Usa o texto original como descrição do solicitante em pedidos antigos.
        cursor.execute('''
            UPDATE pedidos
            SET descricao_solicitante = descricao
            WHERE descricao_solicitante IS NULL AND descricao IS NOT NULL
        ''')
        # Metadados dos arquivos tecnicos anexados a cada pedido.
        # Os bytes dos arquivos ficam em pasta privada, fora do SQLite.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anexos_pedidos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pedido_id INTEGER NOT NULL REFERENCES pedidos(id),
                enviado_por INTEGER NOT NULL REFERENCES usuarios(id),
                nome_original TEXT NOT NULL,
                nome_armazenado TEXT NOT NULL UNIQUE,
                tipo_mime TEXT NOT NULL,
                tamanho_bytes INTEGER NOT NULL,
                criado_em TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_anexos_pedido
            ON anexos_pedidos(pedido_id)
        """)
        # Um pedido pode ter varias propostas, inclusive revisoes.
        # Valores monetarios em centavos evitam imprecisao com FLOAT.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orcamentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pedido_id INTEGER NOT NULL REFERENCES pedidos(id),
                numero_revisao INTEGER NOT NULL CHECK (numero_revisao >= 1),
                valor_orcado_centavos INTEGER NOT NULL CHECK (valor_orcado_centavos >= 0),
                valor_fechado_centavos INTEGER CHECK (valor_fechado_centavos >= 0),
                situacao TEXT NOT NULL DEFAULT 'apresentado'
                    CHECK (situacao IN ('apresentado', 'aprovado', 'recusado', 'substituido')),
                apresentado_em TEXT NOT NULL,
                decidido_em TEXT,
                observacoes TEXT,
                criado_por INTEGER NOT NULL REFERENCES usuarios(id),
                criado_em TEXT NOT NULL,
                UNIQUE (pedido_id, numero_revisao)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_orcamentos_pedido
            ON orcamentos(pedido_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_orcamentos_apresentado_em
            ON orcamentos(apresentado_em)
        """)
        conexao.commit()
    except Exception:
        conexao.rollback()
        raise
    finally:
        conexao.close()
