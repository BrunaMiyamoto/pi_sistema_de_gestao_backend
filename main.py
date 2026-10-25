from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

import jwt
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Depends, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

from database import criar_tabelas, conectar_banco


load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

if len(JWT_SECRET_KEY) < 32:
    raise RuntimeError("Configure JWT_SECRET_KEY no arquivo .env com pelo menos 32 caracteres.")

if JWT_ALGORITHM != "HS256":
    raise RuntimeError("JWT_ALGORITHM deve ser HS256 nesta versão.")

if JWT_EXPIRE_MINUTES <= 0:
    raise RuntimeError("JWT_EXPIRE_MINUTES precisa ser maior que zero.")

app = FastAPI()

# Permite requisições do frontend Vue/Vite durante o desenvolvimento local.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

criar_tabelas()

password_hash = PasswordHash.recommended()
seguranca = HTTPBearer()

PERFIS_VALIDOS = [
    "administrador",
    "funcionario",
    "solicitante"
]


# Dados recebidos ao criar uma solicitacao
class PedidoCriar(BaseModel):
    prazo: str
    descricao_solicitante: str = Field(min_length=1)


# Dados preenchidos pela Ferramentaria ao atualizar uma solicitacao
class PedidoAtualizar(BaseModel):
    status: str
    feedback: str = ""
    descricao_ferramentaria: str | None = None


# Estrutura para cadastrar usuarios
class UsuarioCriar(BaseModel):
    nome: str = Field(min_length=1)
    email: EmailStr
    senha: str = Field(min_length=8)
    perfil: str = "solicitante"


# Estrutura para atualizar usuarios
class UsuarioAtualizar(BaseModel):
    nome: str = Field(min_length=1)
    email: EmailStr
    perfil: str


# Dados recebidos no login
class LoginDados(BaseModel):
    email: EmailStr
    senha: str


# Validar credenciais e devolver token JWT
@app.post("/login")
def login(dados: LoginDados):
    conexao = conectar_banco()
    try:
        usuario = conexao.execute(
            "SELECT id, nome, email, senha, perfil FROM usuarios WHERE email = ?",
            (str(dados.email).lower(),)
        ).fetchone()
    finally:
        conexao.close()

    # Erro genérico, sem informar se o e-mail existe.
    if usuario is None:
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    try:
        senha_correta = password_hash.verify(dados.senha, usuario["senha"])
    except (ValueError, TypeError):
        # Permite lidar com registros legados que não contêm um hash Argon2 válido.
        senha_correta = False

    if not senha_correta:
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    expira = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": str(usuario["id"]), "exp": expira},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return {"access_token": token, "token_type": "bearer"}


# Identifica o usuário atual usando o token enviado no cabeçalho Authorization.
def usuario_atual(
    credenciais: HTTPAuthorizationCredentials = Depends(seguranca)
):
    try:
        dados = jwt.decode(
            credenciais.credentials,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp"]}
        )
        usuario_id = int(dados["sub"])
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

    conexao = conectar_banco()
    try:
        usuario = conexao.execute(
            "SELECT id, nome, email, perfil FROM usuarios WHERE id = ?",
            (usuario_id,)
        ).fetchone()
        if usuario is None:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        return dict(usuario)
    finally:
        conexao.close()


def exigir_funcionario(usuario: dict = Depends(usuario_atual)):
    if usuario["perfil"] not in ("funcionario", "administrador"):
        raise HTTPException(status_code=403, detail="Acesso reservado à Ferramentaria")
    return usuario


def exigir_administrador(usuario: dict = Depends(usuario_atual)):
    if usuario["perfil"] != "administrador":
        raise HTTPException(status_code=403, detail="Acesso reservado ao administrador")
    return usuario


# Página inicial da API
@app.get("/")
def inicio():
    return {"mensagem": "Backend da Ferramentaria funcionando!"}


# Listar ferramentas
@app.get("/ferramentas")
def listar_ferramentas():
    conexao = conectar_banco()

    try:
        ferramentas = conexao.execute(
            "SELECT id, nome FROM ferramentas ORDER BY id"
        ).fetchall()

        return [dict(ferramenta) for ferramenta in ferramentas]
    finally:
        conexao.close()


# Buscar pedidos ativos com filtros opcionais.
# "data" usa AAAA-MM-DD; "mes" usa AAAA-MM.
# Solicitantes continuam limitados aos pedidos da própria conta.
@app.get("/pedidos")
def listar_pedidos(
    data: str | None = Query(default=None, description="Data de abertura: AAAA-MM-DD"),
    mes: str | None = Query(default=None, description="Mês de abertura: AAAA-MM"),
    descricao: str | None = Query(default=None, description="Texto na descrição do pedido"),
    solicitante: str | None = Query(default=None, description="Nome do solicitante"),
    usuario: dict = Depends(usuario_atual),
):
    def escapar_like(texto: str) -> str:
        # Trata %, _ e barra invertida como caracteres literais.
        return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    condicoes = ["excluido = 0"]
    parametros = []

    if usuario["perfil"] not in ("funcionario", "administrador"):
        condicoes.append("usuario_id = ?")
        parametros.append(usuario["id"])

    if data is not None:
        try:
            data_valida = date.fromisoformat(data)
            if data_valida.isoformat() != data:
                raise ValueError()
        except ValueError:
            raise HTTPException(status_code=400, detail="Data inválida. Use AAAA-MM-DD")
        condicoes.append("data = ?")
        parametros.append(data)

    if mes is not None:
        try:
            if len(mes) != 7 or mes[4] != "-":
                raise ValueError()
            date.fromisoformat(mes + "-01")
        except ValueError:
            raise HTTPException(status_code=400, detail="Mês inválido. Use AAAA-MM")
        condicoes.append("substr(data, 1, 7) = ?")
        parametros.append(mes)

    if descricao is not None and descricao.strip():
        condicoes.append("(COALESCE(descricao_solicitante, descricao, '') LIKE ? ESCAPE '\\' OR COALESCE(descricao_ferramentaria, '') LIKE ? ESCAPE '\\')")
        busca = "%" + escapar_like(descricao.strip()) + "%"
        parametros.extend([busca, busca])

    if solicitante is not None and solicitante.strip():
        condicoes.append("solicitante LIKE ? ESCAPE '\\'")
        parametros.append("%" + escapar_like(solicitante.strip()) + "%")

    sql = "SELECT * FROM pedidos WHERE " + " AND ".join(condicoes) + " ORDER BY id"
    conexao = conectar_banco()
    try:
        pedidos = conexao.execute(sql, parametros).fetchall()
        return [dict(pedido) for pedido in pedidos]
    finally:
        conexao.close()


# Consultar um pedido pelo ID, respeitando as permissões
@app.get("/pedidos/{pedido_id}")
def consultar_pedido(pedido_id: int, usuario: dict = Depends(usuario_atual)):
    conexao = conectar_banco()
    try:
        pedido = conexao.execute(
            "SELECT * FROM pedidos WHERE id = ? AND excluido = 0",
            (pedido_id,)
        ).fetchone()
        if pedido is None:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        if usuario["perfil"] == "solicitante" and pedido["usuario_id"] != usuario["id"]:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        return dict(pedido)
    finally:
        conexao.close()


# Cadastrar pedido sem exigir tipo de ferramenta
@app.post("/pedidos", status_code=201)
def criar_pedido(pedido: PedidoCriar, usuario: dict = Depends(usuario_atual)):
    descricao = pedido.descricao_solicitante.strip()
    if not descricao:
        raise HTTPException(status_code=400, detail="A descricao da solicitacao nao pode estar vazia")

    conexao = conectar_banco()
    try:
        hoje = date.today().isoformat()
        cursor = conexao.execute("""
            INSERT INTO pedidos (
                data, solicitante, ferramenta_id, prazo,
                status, abertura, descricao, descricao_solicitante,
                descricao_ferramentaria, usuario_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            hoje,
            usuario["nome"],
            None,
            pedido.prazo,
            "andamento",
            hoje,
            descricao,  # Mantido para compatibilidade com registros antigos
            descricao,
            None,
            usuario["id"]
        ))
        conexao.commit()
        novo_pedido = conexao.execute(
            "SELECT * FROM pedidos WHERE id = ?",
            (cursor.lastrowid,)
        ).fetchone()
        return dict(novo_pedido)
    finally:
        conexao.close()


# Atualizar pedido: apenas funcionarios e administradores da Ferramentaria
@app.put("/pedidos/{pedido_id}")
def atualizar_pedido(
    pedido_id: int,
    dados: PedidoAtualizar,
    usuario: dict = Depends(exigir_funcionario)
):
    conexao = conectar_banco()
    try:
        pedido = conexao.execute(
            "SELECT * FROM pedidos WHERE id = ? AND excluido = 0",
            (pedido_id,)
        ).fetchone()

        if pedido is None:
            raise HTTPException(status_code=404, detail="Pedido nao encontrado")

        if dados.status not in ["andamento", "aguardando", "concluida"]:
            raise HTTPException(status_code=400, detail="Status invalido")

        atendido = (
            date.today().isoformat() if dados.status == "concluida" else None
        )

        # Se o campo nao for enviado, preserva a descricao da Ferramentaria.
        descricao_ferramentaria = (
            pedido["descricao_ferramentaria"]
            if dados.descricao_ferramentaria is None
            else dados.descricao_ferramentaria
        )

        conexao.execute("""
            UPDATE pedidos
            SET status = ?, feedback = ?, atendido = ?,
                descricao_ferramentaria = ?
            WHERE id = ? AND excluido = 0
        """, (
            dados.status,
            dados.feedback,
            atendido,
            descricao_ferramentaria,
            pedido_id
        ))
        conexao.commit()
        atualizado = conexao.execute(
            "SELECT * FROM pedidos WHERE id = ?",
            (pedido_id,)
        ).fetchone()
        return dict(atualizado)
    finally:
        conexao.close()


# Excluir pedido logicamente
@app.delete("/pedidos/{pedido_id}")
def excluir_pedido(pedido_id: int, usuario: dict = Depends(exigir_funcionario)):
    conexao = conectar_banco()

    try:
        pedido = conexao.execute(
            "SELECT id FROM pedidos WHERE id = ? AND excluido = 0",
            (pedido_id,)
        ).fetchone()

        if pedido is None:
            raise HTTPException(
                status_code=404,
                detail="Pedido não encontrado ou já excluído"
            )

        conexao.execute(
            "UPDATE pedidos SET excluido = 1 WHERE id = ?",
            (pedido_id,)
        )

        conexao.commit()

        return {
            "mensagem": "Pedido excluído com sucesso",
            "pedido_id": pedido_id
        }
    finally:
        conexao.close()


# Listar usuarios sem mostrar senhas
@app.get("/usuarios")
def listar_usuarios(usuario: dict = Depends(exigir_administrador)):
    conexao = conectar_banco()

    try:
        usuarios = conexao.execute("""
            SELECT id, nome, email, perfil
            FROM usuarios
            ORDER BY id
        """).fetchall()

        return [dict(usuario) for usuario in usuarios]
    finally:
        conexao.close()


# Cadastrar usuario com senha protegida
@app.post("/usuarios", status_code=201)
def criar_usuario(usuario: UsuarioCriar):
    # Cadastro público: nunca permitir que alguém se cadastre como funcionário ou administrador.
    if usuario.perfil != "solicitante":
        raise HTTPException(
            status_code=400,
            detail="Cadastros públicos devem usar o perfil solicitante"
        )

    nome = usuario.nome.strip()

    if not nome:
        raise HTTPException(
            status_code=400,
            detail="O nome não pode estar vazio"
        )

    senha_protegida = password_hash.hash(usuario.senha)

    conexao = conectar_banco()

    try:
        cursor = conexao.execute("""
            INSERT INTO usuarios (nome, email, senha, perfil)
            VALUES (?, ?, ?, ?)
        """, (
            nome,
            str(usuario.email).lower(),
            senha_protegida,
            usuario.perfil
        ))

        conexao.commit()

        novo_usuario = conexao.execute("""
            SELECT id, nome, email, perfil
            FROM usuarios
            WHERE id = ?
        """, (cursor.lastrowid,)).fetchone()

        return dict(novo_usuario)

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Este e-mail já está cadastrado"
        )

    finally:
        conexao.close()


# Atualizar nome, email e perfil de um usuario
@app.put("/usuarios/{usuario_id}")
def atualizar_usuario(usuario_id: int, dados: UsuarioAtualizar, usuario_logado: dict = Depends(exigir_administrador)):
    if dados.perfil not in PERFIS_VALIDOS:
        raise HTTPException(
            status_code=400,
            detail="Perfil inválido"
        )

    nome = dados.nome.strip()

    if not nome:
        raise HTTPException(
            status_code=400,
            detail="O nome não pode estar vazio"
        )

    conexao = conectar_banco()

    try:
        usuario = conexao.execute(
            "SELECT id FROM usuarios WHERE id = ?",
            (usuario_id,)
        ).fetchone()

        if usuario is None:
            raise HTTPException(
                status_code=404,
                detail="Usuário não encontrado"
            )

        conexao.execute("""
            UPDATE usuarios
            SET nome = ?, email = ?, perfil = ?
            WHERE id = ?
        """, (
            nome,
            str(dados.email).lower(),
            dados.perfil,
            usuario_id
        ))

        conexao.commit()

        usuario_atualizado = conexao.execute("""
            SELECT id, nome, email, perfil
            FROM usuarios
            WHERE id = ?
        """, (usuario_id,)).fetchone()

        return dict(usuario_atualizado)

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Este e-mail já está cadastrado"
        )

    finally:
        conexao.close()


# ==============================================================
# ANEXOS TÉCNICOS - acesso exclusivo à Ferramentaria
# ==============================================================
# A pasta não é exposta como arquivos estáticos/publicamente.
PASTA_ANEXOS = Path(__file__).resolve().parent / "arquivos_privados"
LIMITE_ANEXO_BYTES = 20 * 1024 * 1024  # 20 MB por arquivo
EXTENSOES_PERMITIDAS = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".dxf", ".dwg"}
TIPOS_ARQUIVO = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".dxf": "application/dxf",
    ".dwg": "application/acad",
}


def verificar_pedido_ativo(conexao, pedido_id: int):
    registro = conexao.execute(
        "SELECT id FROM pedidos WHERE id = ? AND excluido = 0", (pedido_id,)
    ).fetchone()
    if registro is None:
        raise HTTPException(status_code=404, detail="Pedido não encontrado")


def metadados_anexo(registro):
    return dict(registro)


@app.post("/pedidos/{pedido_id}/anexos", status_code=201)
async def enviar_anexo(
    pedido_id: int,
    arquivo: UploadFile = File(...),
    usuario: dict = Depends(exigir_funcionario),
):
    # O nome original serve apenas para exibição, nunca para criar um caminho.
    nome_original = (arquivo.filename or "").replace("\\", "/").split("/")[-1]
    extensao = Path(nome_original).suffix.lower()
    if not nome_original or extensao not in EXTENSOES_PERMITIDAS:
        raise HTTPException(
            status_code=400,
            detail="Formato inválido. Envie PDF, PNG, JPG, JPEG, WEBP, DXF ou DWG.",
        )

    conexao = conectar_banco()
    destino = None
    try:
        verificar_pedido_ativo(conexao, pedido_id)
        PASTA_ANEXOS.mkdir(parents=True, exist_ok=True)
        nome_armazenado = f"{uuid4().hex}{extensao}"
        destino = PASTA_ANEXOS / nome_armazenado

        tamanho = 0
        # Leitura por blocos evita carregar o arquivo inteiro na RAM.
        with destino.open("xb") as saida:
            while True:
                bloco = await arquivo.read(1024 * 1024)
                if not bloco:
                    break
                tamanho += len(bloco)
                if tamanho > LIMITE_ANEXO_BYTES:
                    raise HTTPException(status_code=413, detail="O anexo deve ter no máximo 20 MB")
                saida.write(bloco)

        if tamanho == 0:
            raise HTTPException(status_code=400, detail="Arquivo vazio")

        criado_em = datetime.now(timezone.utc).isoformat()
        cursor = conexao.execute("""
            INSERT INTO anexos_pedidos
                (pedido_id, enviado_por, nome_original, nome_armazenado,
                 tipo_mime, tamanho_bytes, criado_em)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            pedido_id, usuario["id"], nome_original, nome_armazenado,
            TIPOS_ARQUIVO[extensao], tamanho, criado_em,
        ))
        conexao.commit()
        registro = conexao.execute(
            "SELECT id, pedido_id, enviado_por, nome_original, tipo_mime, "
            "tamanho_bytes, criado_em FROM anexos_pedidos WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        return metadados_anexo(registro)
    except Exception:
        conexao.rollback()
        if destino is not None:
            destino.unlink(missing_ok=True)
        raise
    finally:
        await arquivo.close()
        conexao.close()


@app.get("/pedidos/{pedido_id}/anexos")
def listar_anexos(pedido_id: int, usuario: dict = Depends(exigir_funcionario)):
    conexao = conectar_banco()
    try:
        verificar_pedido_ativo(conexao, pedido_id)
        registros = conexao.execute("""
            SELECT id, pedido_id, enviado_por, nome_original, tipo_mime,
                   tamanho_bytes, criado_em
            FROM anexos_pedidos
            WHERE pedido_id = ?
            ORDER BY id
        """, (pedido_id,)).fetchall()
        return [metadados_anexo(r) for r in registros]
    finally:
        conexao.close()


@app.get("/pedidos/{pedido_id}/anexos/{anexo_id}/download")
def baixar_anexo(
    pedido_id: int,
    anexo_id: int,
    usuario: dict = Depends(exigir_funcionario),
):
    conexao = conectar_banco()
    try:
        verificar_pedido_ativo(conexao, pedido_id)
        registro = conexao.execute("""
            SELECT nome_original, nome_armazenado, tipo_mime
            FROM anexos_pedidos
            WHERE id = ? AND pedido_id = ?
        """, (anexo_id, pedido_id)).fetchone()
        if registro is None:
            raise HTTPException(status_code=404, detail="Anexo não encontrado")

        # Defesa adicional se algum valor armazenado no banco for adulterado.
        nome_armazenado = registro["nome_armazenado"]
        if Path(nome_armazenado).name != nome_armazenado:
            raise HTTPException(status_code=500, detail="Nome interno do anexo inválido")
        caminho = PASTA_ANEXOS / nome_armazenado
        if not caminho.is_file():
            raise HTTPException(status_code=404, detail="Arquivo não encontrado no servidor")

        return FileResponse(
            path=str(caminho),
            media_type="application/octet-stream",
            filename=registro["nome_original"],
            content_disposition_type="attachment",
        )
    finally:
        conexao.close()



# Valores recebidos em reais; armazenados como centavos inteiros no SQLite.
class OrcamentoCriar(BaseModel):
    valor_orcado: Decimal = Field(gt=0, max_digits=14, decimal_places=2)
    apresentado_em: date
    observacoes: str = ""


class OrcamentoDecidir(BaseModel):
    situacao: str  # aprovado ou recusado
    valor_fechado: Decimal | None = Field(default=None, ge=0, max_digits=14, decimal_places=2)


def para_centavos(valor: Decimal) -> int:
    return int((valor * 100).to_integral_value(rounding=ROUND_HALF_UP))


def serializar_orcamento(registro):
    orcamento = dict(registro)
    orcamento["valor_orcado"] = f'{Decimal(orcamento["valor_orcado_centavos"]) / 100:.2f}'
    centavos = orcamento["valor_fechado_centavos"]
    orcamento["valor_fechado"] = f'{Decimal(centavos) / 100:.2f}' if centavos is not None else None
    return orcamento


def obter_orcamento(conexao, pedido_id: int, orcamento_id: int):
    registro = conexao.execute(
        "SELECT * FROM orcamentos WHERE id = ? AND pedido_id = ?", (orcamento_id, pedido_id)
    ).fetchone()
    if registro is None:
        raise HTTPException(status_code=404, detail="Orçamento não encontrado")
    return registro


@app.post("/pedidos/{pedido_id}/orcamentos", status_code=201)
def cadastrar_orcamento(
    pedido_id: int,
    dados: OrcamentoCriar,
    usuario: dict = Depends(exigir_funcionario),
):
    conexao = conectar_banco()
    try:
        # Transação de escrita impede números de revisão repetidos em requisições simultâneas.
        conexao.execute("BEGIN IMMEDIATE")
        verificar_pedido_ativo(conexao, pedido_id)
        ultima = conexao.execute(
            "SELECT * FROM orcamentos WHERE pedido_id = ? ORDER BY numero_revisao DESC LIMIT 1",
            (pedido_id,),
        ).fetchone()
        if ultima is not None and ultima["situacao"] == "aprovado":
            raise HTTPException(status_code=409, detail="Já existe um orçamento aprovado neste pedido")
        if ultima is not None and ultima["situacao"] == "apresentado":
            conexao.execute(
                "UPDATE orcamentos SET situacao = 'substituido' WHERE id = ?",
                (ultima["id"],),
            )
        revisao = ultima["numero_revisao"] + 1 if ultima is not None else 1
        cursor = conexao.execute("""
            INSERT INTO orcamentos
              (pedido_id, numero_revisao, valor_orcado_centavos, situacao,
               apresentado_em, observacoes, criado_por, criado_em)
            VALUES (?, ?, ?, 'apresentado', ?, ?, ?, ?)
        """, (
            pedido_id, revisao, para_centavos(dados.valor_orcado),
            dados.apresentado_em.isoformat(), dados.observacoes.strip(),
            usuario["id"], datetime.now(timezone.utc).isoformat(),
        ))
        novo = obter_orcamento(conexao, pedido_id, cursor.lastrowid)
        conexao.commit()
        return serializar_orcamento(novo)
    except Exception:
        conexao.rollback()
        raise
    finally:
        conexao.close()


@app.get("/pedidos/{pedido_id}/orcamentos")
def listar_orcamentos(pedido_id: int, usuario: dict = Depends(exigir_funcionario)):
    conexao = conectar_banco()
    try:
        verificar_pedido_ativo(conexao, pedido_id)
        registros = conexao.execute(
            "SELECT * FROM orcamentos WHERE pedido_id = ? ORDER BY numero_revisao",
            (pedido_id,),
        ).fetchall()
        return [serializar_orcamento(r) for r in registros]
    finally:
        conexao.close()


@app.put("/pedidos/{pedido_id}/orcamentos/{orcamento_id}/decisao")
def decidir_orcamento(
    pedido_id: int,
    orcamento_id: int,
    dados: OrcamentoDecidir,
    usuario: dict = Depends(exigir_funcionario),
):
    if dados.situacao not in ("aprovado", "recusado"):
        raise HTTPException(status_code=400, detail="Situação deve ser aprovado ou recusado")
    if dados.situacao == "recusado" and dados.valor_fechado is not None:
        raise HTTPException(status_code=400, detail="Orçamento recusado não possui valor fechado")
    if dados.situacao == "aprovado" and dados.valor_fechado is None:
        raise HTTPException(status_code=400, detail="Informe o valor fechado do orçamento aprovado")

    conexao = conectar_banco()
    try:
        conexao.execute("BEGIN IMMEDIATE")
        verificar_pedido_ativo(conexao, pedido_id)
        registro = obter_orcamento(conexao, pedido_id, orcamento_id)
        if registro["situacao"] != "apresentado":
            raise HTTPException(status_code=409, detail="Somente orçamentos apresentados podem ser decididos")
        ultima = conexao.execute(
            "SELECT id FROM orcamentos WHERE pedido_id = ? ORDER BY numero_revisao DESC LIMIT 1",
            (pedido_id,),
        ).fetchone()
        if ultima["id"] != orcamento_id:
            raise HTTPException(status_code=409, detail="Somente a revisão mais recente pode ser decidida")
        conexao.execute("""
            UPDATE orcamentos
            SET situacao = ?, valor_fechado_centavos = ?, decidido_em = ?
            WHERE id = ?
        """, (
            dados.situacao,
            para_centavos(dados.valor_fechado) if dados.valor_fechado is not None else None,
            datetime.now(timezone.utc).date().isoformat(),
            orcamento_id,
        ))
        atualizado = obter_orcamento(conexao, pedido_id, orcamento_id)
        conexao.commit()
        return serializar_orcamento(atualizado)
    except Exception:
        conexao.rollback()
        raise
    finally:
        conexao.close()


# Relatorio comercial mensal da Ferramentaria.
# Permissoes: apenas funcionario e administrador.
# Uma revisao substituida nao entra na soma dos valores orcados,
# mas conta como proposta apresentada para fins de volume de trabalho.
@app.get("/relatorios/comercial")
def relatorio_comercial(
    mes: str = Query(description="Mes de referencia no formato AAAA-MM (ex.: 2026-10)"),
    usuario: dict = Depends(exigir_funcionario),
):
    try:
        if len(mes) != 7 or mes[4] != "-" or not (mes[:4] + mes[5:]).isdigit():
            raise ValueError()
        date.fromisoformat(mes + "-01")
    except ValueError:
        raise HTTPException(status_code=400, detail="Mes invalido. Use AAAA-MM")

    conexao = conectar_banco()
    try:
        # Hit rate por safra de pedidos: entre os pedidos abertos neste mes,
        # quantos ja receberam ao menos um orcamento (mesmo depois da abertura).
        recebidos = conexao.execute("""
            SELECT COUNT(*) AS total
            FROM pedidos
            WHERE excluido = 0 AND substr(data, 1, 7) = ?
        """, (mes,)).fetchone()["total"]

        orcados = conexao.execute("""
            SELECT COUNT(*) AS total
            FROM pedidos AS p
            WHERE p.excluido = 0 AND substr(p.data, 1, 7) = ?
              AND EXISTS (
                  SELECT 1 FROM orcamentos AS o WHERE o.pedido_id = p.id
              )
        """, (mes,)).fetchone()["total"]

        # Volume de propostas efetivamente apresentadas durante o mes,
        # inclusive revisoes que hoje estejam marcadas como substituidas.
        apresentadas = conexao.execute("""
            SELECT COUNT(*) AS total
            FROM orcamentos AS o
            JOIN pedidos AS p ON p.id = o.pedido_id
            WHERE p.excluido = 0 AND substr(o.apresentado_em, 1, 7) = ?
        """, (mes,)).fetchone()["total"]

        # Para os valores comerciais consideramos somente a ultima revisao
        # de cada pedido, apresentada durante o mes selecionado.
        # Isso evita somar o mesmo pedido diversas vezes.
        resumo = conexao.execute("""
            SELECT
                COUNT(*) AS orcamentos_vigentes,
                COALESCE(SUM(CASE WHEN o.situacao = 'aprovado' THEN 1 ELSE 0 END), 0)
                    AS orcamentos_aprovados,
                COALESCE(SUM(o.valor_orcado_centavos), 0) AS valor_orcado_centavos,
                COALESCE(SUM(CASE WHEN o.situacao = 'aprovado'
                                  THEN COALESCE(o.valor_fechado_centavos, 0)
                                  ELSE 0 END), 0) AS valor_fechado_centavos
            FROM orcamentos AS o
            JOIN pedidos AS p ON p.id = o.pedido_id
            WHERE p.excluido = 0
              AND substr(o.apresentado_em, 1, 7) = ?
              AND o.numero_revisao = (
                  SELECT MAX(ou.numero_revisao)
                  FROM orcamentos AS ou WHERE ou.pedido_id = o.pedido_id
              )
              AND o.situacao != 'substituido'
        """, (mes,)).fetchone()

        total_orcado = int(resumo["valor_orcado_centavos"])
        total_fechado = int(resumo["valor_fechado_centavos"])

        def percentual(numerador: int, denominador: int) -> str | None:
            if denominador == 0:
                return None  # Nao ha base para calcular a taxa.
            return str(
                (Decimal(numerador) * Decimal(100) / Decimal(denominador))
                .quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            )

        def reais(centavos: int) -> str:
            return f"{Decimal(centavos) / Decimal(100):.2f}"

        return {
            "mes": mes,
            "pedidos_recebidos": recebidos,
            "pedidos_orcados": orcados,
            "hit_rate_percentual": percentual(orcados, recebidos),
            "propostas_apresentadas": apresentadas,
            "orcamentos_vigentes": resumo["orcamentos_vigentes"],
            "orcamentos_aprovados": resumo["orcamentos_aprovados"],
            "valor_orcado_centavos": total_orcado,
            "valor_fechado_centavos": total_fechado,
            "valor_orcado": reais(total_orcado),
            "valor_fechado": reais(total_fechado),
            "win_rate_percentual": percentual(total_fechado, total_orcado),
            "observacoes": {
                "hit_rate": "Pedidos ativos abertos no mes que receberam ao menos um orcamento / pedidos ativos abertos no mes.",
                "propostas_apresentadas": "Conta todas as propostas do mes, inclusive revisoes posteriormente substituidas.",
                "win_rate": "Valores fechados / valores orcados das ultimas revisoes por pedido, apresentadas no mes.",
                "sem_denominador": "Taxas retornam null quando nao existe base para o calculo.",
            },
        }
    finally:
        conexao.close()
