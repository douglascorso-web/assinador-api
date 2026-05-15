"""
Módulo de assinatura PDF — pyhanko, duas colunas, padrão ICP-Brasil.

Layout:
  ┌─────────────┬──────────────────────────────────────────┐
  │  NOME       │ Assinado digitalmente por NOME:DOC       │
  │  SOBRENOME  │ ND: C=BR, O=ICP-Brasil, ...             │
  │  DOC        │ Razao / Localizacao / Data               │
  └─────────────┴──────────────────────────────────────────┘

Coluna esquerda → background (RawContent)
Coluna direita  → TextStampStyle com inner_content_layout (margin_left=div)
"""

import io
import os
import re
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
from pyhanko.pdf_utils.layout import BoxConstraints, SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.pdf_utils.text import TextBoxStyle


def _get_attr(cert, oid):
    try:
        return cert.subject.get_attributes_for_oid(oid)[0].value
    except Exception:
        return ''


def _montar_nd(cert) -> str:
    partes = []
    for oid, label in [
        (NameOID.COUNTRY_NAME,             'C'),
        (NameOID.ORGANIZATION_NAME,        'O'),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, 'OU'),
        (NameOID.COMMON_NAME,              'CN'),
    ]:
        v = _get_attr(cert, oid)
        if v:
            partes.append(f'{label}={v}')
    return ', '.join(partes)


def _esc(s: str) -> str:
    return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _quebrar_nome(nome: str, max_chars: int = 9) -> list:
    palavras = nome.split()
    linhas = []
    linha = ''
    for p in palavras:
        if len(linha) + len(p) + (1 if linha else 0) <= max_chars:
            linha = (linha + ' ' + p).strip()
        else:
            if linha:
                linhas.append(linha)
            linha = p
    if linha:
        linhas.append(linha)
    return linhas


def _quebrar_texto(texto: str, max_chars: int) -> str:
    """Quebra texto longo em múltiplas linhas separadas por \\n."""
    if len(texto) <= max_chars:
        return texto
    linhas = []
    while texto:
        if len(texto) <= max_chars:
            linhas.append(texto)
            break
        c = texto.rfind(' ', 0, max_chars)
        if c == -1:
            c = max_chars
        linhas.append(texto[:c])
        texto = texto[c:].lstrip()
    return '\n'.join(linhas)


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


def assinar_pdf(
    pdf_bytes: bytes,
    pfx_bytes: bytes,
    pfx_senha: bytes,
    config:    dict,
) -> bytes:
    # Carregar signer
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

    if ':' in cn:
        nome, doc = cn.split(':', 1)
        nome, doc = nome.strip(), doc.strip()
    else:
        nome, doc = cn, ''

    # Dimensões do campo
    MM     = 2.834645
    x1     = config.get('x1_mm',  8.0) * MM
    y1     = config.get('y1_mm',  5.0) * MM
    x2     = config.get('x2_mm', 91.0) * MM
    y2     = config.get('y2_mm', 20.0) * MM
    W_f    = x2 - x1
    H_f    = y2 - y1
    razao  = config.get('razao', 'Eu sou o autor deste documento')
    local  = config.get('local', 'Brasil')
    pagina = int(config.get('pagina', -1))

    with io.BytesIO(pdf_bytes) as fbuf:
        reader    = PdfFileReader(fbuf)
        n_paginas = int(reader.root['/Pages'].get_object()['/Count'])
    pagina_idx = max(0, n_paginas + pagina) if pagina < 0 else min(pagina, n_paginas - 1)

    data_hora = datetime.now(timezone.utc).strftime('%Y.%m.%d %H:%M:%S UTC')

    # Layout
    div   = W_f * 0.28
    w_dir = W_f - div - 3

    # Coluna esquerda: nome quebrado
    linhas_esq = _quebrar_nome(nome)
    n_esq      = len(linhas_esq)
    fs_esq     = round(min(div / max(len(l) for l in linhas_esq) * 1.55, H_f / n_esq * 0.82), 2)
    fs_doc     = round(max(fs_esq * 0.52, 5.0), 2)

    # Background: coluna esquerda
    bg  = f'0 0 0 RG 0.4 w {div:.3f} 1 m {div:.3f} {H_f-1:.3f} l S\n'
    bg += f'BT\n0 0 0 rg\n/F1 {fs_esq:.2f} Tf\n2 {H_f - fs_esq*1.1:.2f} Td\n({_esc(linhas_esq[0])}) Tj\n'
    for l in linhas_esq[1:]:
        bg += f'0 {-fs_esq*1.1:.2f} Td\n({_esc(l)}) Tj\n'
    bg += 'ET\n'
    if doc:
        y_doc = max(H_f - fs_esq*1.1 - n_esq * fs_esq*1.1, 1.5)
        bg += f'BT\n0 0 0 rg\n/F1 {fs_doc:.2f} Tf\n2 {y_doc:.2f} Td\n({_esc(doc)}) Tj\nET\n'

    background = RawContent(
        data=bg.encode('latin-1'),
        box=BoxConstraints(width=W_f, height=H_f),
    )

    # Coluna direita: stamp_text com quebra automática
    # font_size=6 → char_width Courier ≈ 3.6pt → max_chars = w_dir/3.6
    font_dir   = 6
    max_chars  = max(1, int(w_dir / (font_dir * 0.6)))
    nd_curto   = re.sub(r', OU=[^,]+', '', nd)  # remover OU= se muito longo

    stamp_text = '\n'.join([
        _quebrar_texto(f"Assinado digitalmente por {cn}", max_chars),
        _quebrar_texto(f"ND: {nd_curto}", max_chars),
        f"Razao: {razao}",
        f"Localizacao: {local}",
        f"Data: {data_hora}",
    ])

    # inner_content_layout: empurra o text box para após a divisória
    inner_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MAX,
        margins=Margins(left=int(div) + 2, right=1, top=1, bottom=1),
    )

    style = TextStampStyle(
        stamp_text=stamp_text,
        timestamp_format='%Y.%m.%d %H:%M:%S UTC',
        background=background,
        background_opacity=1.0,
        border_width=1,
        inner_content_layout=inner_layout,
        text_box_style=TextBoxStyle(font_size=font_dir),
    )

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
