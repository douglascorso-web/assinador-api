"""
Módulo de assinatura PDF — pyhanko + aparência em duas colunas padrão ICP-Brasil.

Layout do selo:
  ┌─────────────┬──────────────────────────────────────────┐
  │  NOME       │ Assinado digitalmente por NOME:DOC       │
  │  SOBRENOME  │ ND: C=BR, O=ICP-Brasil, ...             │
  │  NOME:      │ Razao: ...                               │
  │  DOC        │ Data: YYYY.MM.DD HH:MM:SS UTC            │
  └─────────────┴──────────────────────────────────────────┘

A coluna esquerda é renderizada via background (RawContent),
a coluna direita via TextStampStyle — ambas geradas pelo pyhanko.
"""

import io
import os
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import NameOID

from pyhanko.sign.signers import SimpleSigner, PdfSignatureMetadata, PdfSigner
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import TextStampStyle
from pyhanko.pdf_utils.content import RawContent
from pyhanko.pdf_utils.layout import BoxConstraints


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _get_attr(cert, oid):
    try:
        return cert.subject.get_attributes_for_oid(oid)[0].value
    except Exception:
        return ''


def _montar_nd(cert) -> str:
    partes = []
    for oid, label in [
        (NameOID.COUNTRY_NAME,            'C'),
        (NameOID.ORGANIZATION_NAME,       'O'),
        (NameOID.ORGANIZATIONAL_UNIT_NAME,'OU'),
        (NameOID.COMMON_NAME,             'CN'),
    ]:
        v = _get_attr(cert, oid)
        if v:
            partes.append(f'{label}={v}')
    return ', '.join(partes)


def _esc(s: str) -> str:
    return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _quebrar_linhas(nome: str, max_chars: int = 9):
    palavras = nome.split()
    linhas = []
    linha_atual = ''
    for p in palavras:
        if len(linha_atual) + len(p) + (1 if linha_atual else 0) <= max_chars:
            linha_atual = (linha_atual + ' ' + p).strip()
        else:
            if linha_atual:
                linhas.append(linha_atual)
            linha_atual = p
    if linha_atual:
        linhas.append(linha_atual)
    return linhas


# ─── Validação ───────────────────────────────────────────────────────────────

def carregar_certificado_base64(pfx_bytes: bytes, senha: bytes) -> dict:
    try:
        key, cert, chain = load_key_and_certificates(pfx_bytes, senha)
    except Exception as e:
        raise ValueError(f'Certificado inválido ou senha incorreta: {e}')

    try:
        valid_until = cert.not_valid_after_utc
        valid_from  = cert.not_valid_before_utc
        agora       = datetime.now(timezone.utc)
    except AttributeError:
        valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)
        valid_from  = cert.not_valid_before.replace(tzinfo=timezone.utc)
        agora       = datetime.now(timezone.utc)

    if valid_until < agora:
        raise ValueError(f'Certificado expirado em {valid_until.strftime("%d/%m/%Y")}')

    return {
        'titular':     _get_attr(cert, NameOID.COMMON_NAME),
        'organizacao': _get_attr(cert, NameOID.ORGANIZATION_NAME),
        'valido_de':   valid_from.strftime('%d/%m/%Y'),
        'valido_ate':  valid_until.strftime('%d/%m/%Y'),
        'serial':      str(cert.serial_number),
        'expirado':    False,
    }


# ─── Assinatura ──────────────────────────────────────────────────────────────

def assinar_pdf(
    pdf_bytes: bytes,
    pfx_bytes: bytes,
    pfx_senha: bytes,
    config:    dict,
) -> bytes:
    """
    Assina o PDF com aparência em duas colunas no padrão ICP-Brasil.

    Coluna esquerda : nome grande + identificador (via background RawContent)
    Coluna direita  : texto "Assinado digitalmente por …" (via TextStampStyle)
    """
    # Carregar certificado
    pfx_tmp = tempfile.NamedTemporaryFile(suffix='.pfx', delete=False)
    pfx_tmp.write(pfx_bytes)
    pfx_tmp.close()
    try:
        signer = SimpleSigner.load_pkcs12(pfx_tmp.name, passphrase=pfx_senha)
    except Exception as e:
        raise ValueError(f'Erro ao carregar certificado: {e}')
    finally:
        try: os.unlink(pfx_tmp.name)
        except: pass

    _, cert, _ = load_key_and_certificates(pfx_bytes, pfx_senha)
    cn  = _get_attr(cert, NameOID.COMMON_NAME)
    nd  = _montar_nd(cert)

    # Separar nome e identificador (CPF/CNPJ vem após ':')
    if ':' in cn:
        nome, doc = cn.split(':', 1)
        nome, doc = nome.strip(), doc.strip()
    else:
        nome, doc = cn, ''

    # Configurações do campo
    MM     = 2.834645
    x1     = config.get('x1_mm',  8.0) * MM
    y1     = config.get('y1_mm',  5.0) * MM
    x2     = config.get('x2_mm', 91.0) * MM
    y2     = config.get('y2_mm', 18.0) * MM
    W_f    = x2 - x1
    H_f    = y2 - y1
    razao  = config.get('razao', 'Eu sou o autor deste documento')
    local  = config.get('local', 'Brasil')
    pagina = int(config.get('pagina', -1))

    with io.BytesIO(pdf_bytes) as fbuf:
        reader    = PdfFileReader(fbuf)
        n_paginas = int(reader.root['/Pages'].get_object()['/Count'])
    pagina_idx = max(0, n_paginas + pagina) if pagina < 0 else min(pagina, n_paginas - 1)

    # ── Background: coluna esquerda com nome grande ───────────────────────────
    div    = W_f * 0.28          # largura da coluna esquerda (~28%)
    linhas = _quebrar_linhas(nome)
    n      = len(linhas)
    fs     = round(min(div / max(len(l) for l in linhas) * 1.55, H_f / n * 0.82), 2)
    fs_doc = round(max(fs * 0.52, 5.0), 2)

    bg  = f'0 0 0 RG 0.4 w {div:.3f} 1 m {div:.3f} {H_f-1:.3f} l S\n'
    bg += f'BT\n0 0 0 rg\n/F1 {fs:.2f} Tf\n2 {H_f - fs*1.1:.2f} Td\n({_esc(linhas[0])}) Tj\n'
    for l in linhas[1:]:
        bg += f'0 {-fs*1.1:.2f} Td\n({_esc(l)}) Tj\n'
    bg += 'ET\n'
    if doc:
        y_doc = max(H_f - fs*1.1 - n * fs * 1.1, 1.5)
        bg += f'BT\n0 0 0 rg\n/F1 {fs_doc:.2f} Tf\n2 {y_doc:.2f} Td\n({_esc(doc)}) Tj\nET\n'

    background = RawContent(
        data=bg.encode('latin-1'),
        box=BoxConstraints(width=W_f, height=H_f),
    )

    # ── Coluna direita: texto padrão ICP-Brasil ───────────────────────────────
    stamp_text = (
        "Assinado digitalmente por %(signer)s\n"
        f"ND: {nd}\n"
        f"Razao: {razao}\n"
        f"Localizacao: {local}\n"
        "Data: %(ts)s"
    )
    style = TextStampStyle(
        stamp_text=stamp_text,
        timestamp_format='%Y.%m.%d %H:%M:%S UTC',
        background=background,
        background_opacity=1.0,
        border_width=1,
    )

    # ── Assinar ───────────────────────────────────────────────────────────────
    sig_field = SigFieldSpec(
        sig_field_name='Assinatura_Digital',
        on_page=pagina_idx,
        box=(x1, y1, x2, y2),
    )
    sig_meta = PdfSignatureMetadata(
        field_name='Assinatura_Digital',
        reason=razao,
        location=local,
        name=cn,
    )
    pdf_signer = PdfSigner(sig_meta, signer, stamp_style=style, new_field_spec=sig_field)

    pdf_in  = io.BytesIO(pdf_bytes)
    pdf_out = io.BytesIO()
    pdf_signer.sign_pdf(IncrementalPdfFileWriter(pdf_in), output=pdf_out)

    pdf_out.seek(0)
    resultado = pdf_out.read()

    if resultado[:4] != b'%PDF':
        raise RuntimeError('Resultado da assinatura não é um PDF válido.')
    return resultado
