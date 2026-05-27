"""
Módulo de assinatura PDF — pyhanko, duas colunas, padrão ICP-Brasil.

Layout:
  ┌─────────────┬──────────────────────────────────────────┐
  │  NOME       │ Assinado digitalmente por NOME:DOC       │
  │  SOBRENOME  │ ND: C=BR, O=ICP-Brasil, ...             │
  │  DOC        │ Razao / Localizacao / Data               │
  └─────────────┴──────────────────────────────────────────┘

Coluna esquerda → background (RawContent) com layout calibrado via 2 passagens
Coluna direita  → TextStampStyle com inner_content_layout
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
from pyhanko.pdf_utils.layout import (
    BoxConstraints, SimpleBoxLayoutRule, AxisAlignment, Margins, InnerScaling
)
from pyhanko.pdf_utils.text import TextBoxStyle
from pypdf import PdfReader


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


def _bg_layout():
    """Background alinhado à esquerda/base com margens mínimas."""
    return SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MIN,
        margins=Margins(left=1, right=1, top=1, bottom=1),
        inner_content_scaling=InnerScaling.SHRINK_TO_FIT,
    )


def _extrair_transforms(pdf_bytes, signer, cn, x1, y1_ref, x2, y2_ref,
                         W_f, H_f, stamp_text, inner_layout, font_dir):
    """1a passagem: extrai os transforms reais do AP stream."""
    bg_test = RawContent(data=b"% test", box=BoxConstraints(width=W_f, height=H_f))
    style   = TextStampStyle(
        stamp_text="t\nt\nt\nt\nt",
        background=bg_test, background_opacity=1.0,
        background_layout=_bg_layout(),
        border_width=1,
        inner_content_layout=inner_layout,
        text_box_style=TextBoxStyle(font_size=font_dir),
    )
    meta = PdfSignatureMetadata(field_name='Sig_Test', reason='t', location='t', name=cn)
    spec = SigFieldSpec(sig_field_name='Sig_Test', on_page=0, box=(x1, y1_ref, x2, y2_ref))
    ps   = PdfSigner(meta, signer, stamp_style=style, new_field_spec=spec)
    out  = io.BytesIO()
    ps.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf_bytes), strict=False), output=out)
    out.seek(0)

    r = PdfReader(out)
    for field_ref in r.trailer['/Root']['/AcroForm']['/Fields']:
        fobj = field_ref.get_object()
        if '/AP' not in fobj:
            continue
        for _, v in fobj['/AP'].items():
            ap   = v.get_object()
            data = ap.get_data().decode('latin-1')
            if 'BackgroundGS' not in data:
                continue
            m_bg = re.search(
                r'/BackgroundGS gs ([\d.]+) 0 0 [\d.]+ ([\d.]+) ([\d.]+) cm', data)
            m_tx = re.search(
                r'q ([\d.]+) 0 0 [\d.]+ ([\d.]+) ([\d.]+) cm.*?/Tx BMC', data, re.DOTALL)
            if m_bg and m_tx:
                return {
                    'scale_bg': float(m_bg.group(1)),
                    'off_x_bg': float(m_bg.group(2)),
                    'off_y_bg': float(m_bg.group(3)),
                    'off_x_tx': float(m_tx.group(2)),
                }
    return None


def _montar_background(nome, doc, div_bg, H_bg) -> bytes:
    """
    Monta o stream PDF da coluna esquerda.
    Nome + CPF ficam no MESMO bloco BT...ET para garantir que o CPF
    seja sempre renderizado (evita problemas de clipping em leitores PDF).
    """
    linhas = _quebrar_nome(nome)
    n      = len(linhas)

    # Calcular fs para que nome (n linhas) + gap + CPF caibam em H_bg
    # H_bg ≈ 2 + n*fs*1.1 + fs_doc*0.4 (gap) + fs_doc
    # onde fs_doc = fs*0.52 → H_bg = 2 + fs*(n*1.1 + 0.4*0.52 + 0.52)
    #                                = 2 + fs*(n*1.1 + 0.728)
    if doc:
        fs_altura  = (H_bg - 2) / (n * 1.1 + 1.5)  # +1.5 para reduzir fs_nome ~2pt
    else:
        fs_altura  = (H_bg - 2) / (n * 1.1)

    fs_largura = div_bg / max(len(l) for l in linhas) * 1.32  # reduzido para fonte menor do nome
    fs         = round(min(fs_largura, fs_altura), 2)
    fs_doc     = round(max(fs * 0.82, 6.0), 2)  # maior proporção para harmonia

    y_topo = H_bg - 2 - fs

    # Tudo em um único BT block — garante renderização mesmo com clipping externo
    bg  = f'0 0 0 RG 0.4 w {div_bg:.3f} 1 m {div_bg:.3f} {H_bg-1:.3f} l S\n'
    bg += f'BT\n0 0 0 rg\n/F1 {fs:.2f} Tf\n2 {y_topo:.2f} Td\n({_esc(linhas[0])}) Tj\n'
    for l in linhas[1:]:
        bg += f'0 {-fs*1.1:.2f} Td\n({_esc(l)}) Tj\n'
    if doc:
        gap = 2.0  # gap fixo de 2pt entre nome e CPF
        bg += f'/F1 {fs_doc:.2f} Tf\n0 {-(gap + fs_doc):.2f} Td\n({_esc(doc)}) Tj\n'
    bg += 'ET\n'
    return bg.encode('latin-1')


def assinar_pdf(
    pdf_bytes: bytes,
    pfx_bytes: bytes,
    pfx_senha: bytes,
    config:    dict,
) -> bytes:
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

    if ':' in cn:
        nome, doc = cn.split(':', 1)
        nome, doc = nome.strip(), doc.strip()
    else:
        nome, doc = cn, ''

    MM     = 2.834645
    x1     = config.get('x1_mm',  8.0) * MM
    y1_last  = config.get('y1_mm',  5.0) * MM    # Y da última página
    y1_other = config.get('y1_mm_outras', config.get('y1_mm', 5.0)) * MM  # Y das demais
    x2     = config.get('x2_mm', 120.0) * MM
    y2_last  = config.get('y2_mm',  26.0) * MM
    y2_other = config.get('y2_mm_outras', config.get('y2_mm', 26.0)) * MM
    razao  = config.get('razao', 'Eu sou o autor deste documento')
    local  = config.get('local', 'Brasil')
    pagina_cfg = config.get('pagina', -1)  # int ou 'all'

    with io.BytesIO(pdf_bytes) as fbuf:
        reader    = PdfFileReader(fbuf)
        n_paginas = int(reader.root['/Pages'].get_object()['/Count'])

    if pagina_cfg == 'all':
        paginas_idx = list(range(n_paginas))  # todas as páginas
    else:
        pagina = int(pagina_cfg)
        idx = max(0, n_paginas + pagina) if pagina < 0 else min(pagina, n_paginas - 1)
        paginas_idx = [idx]
    
    ultima_pagina_idx = n_paginas - 1

    # Data/hora no fuso horário de Brasília (UTC-3)
    from datetime import timedelta
    agora_br = datetime.now(timezone.utc) - timedelta(hours=3)
    data_hora = agora_br.strftime('%d/%m/%Y - %H:%M')

    # Para o cálculo do estilo visual, usar dimensões da última página como referência
    W_f = x2 - x1
    H_f = y2_last - y1_last
    div      = W_f * 0.28
    w_dir    = W_f - div - 3
    font_dir = 8
    max_chars = max(1, int(w_dir / (font_dir * 0.6)))

    # Coluna direita: 3 linhas no padrão solicitado
    if ':' in cn:
        nome_parte, doc_parte = cn.split(':', 1)
        nome_parte = nome_parte.strip()
        doc_parte  = doc_parte.strip()
        linha_nome = f"{nome_parte} - CPF: {doc_parte}"
    else:
        linha_nome = cn

    stamp_text = '\n'.join([
        "Assinado digitalmente por:",
        linha_nome,
        data_hora,
    ])

    inner_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MAX,
        margins=Margins(left=int(div) + 2, right=1, top=1, bottom=1),
    )

    # ── 1a passagem: descobrir transforms reais ───────────────────────────────
    pfx_tmp2 = tempfile.NamedTemporaryFile(suffix='.pfx', delete=False)
    pfx_tmp2.write(pfx_bytes)
    pfx_tmp2.close()
    try:
        signer2 = SimpleSigner.load_pkcs12(pfx_tmp2.name, passphrase=pfx_senha)
    finally:
        try: os.unlink(pfx_tmp2.name)
        except: pass

    tr = _extrair_transforms(
        pdf_bytes, signer2, cn, x1, y1_last, x2, y2_last,
        W_f, H_f, stamp_text, inner_layout, font_dir
    )

    if tr:
        div_bg = (tr['off_x_tx'] - tr['off_x_bg']) / tr['scale_bg']
        H_bg   = (H_f - tr['off_y_bg']) / tr['scale_bg']
    else:
        div_bg = div * 0.8
        H_bg   = H_f * 1.1

    # ── 2a passagem: gerar PDF final ─────────────────────────────────────────
    bg_data    = _montar_background(nome, doc, div_bg, H_bg)
    background = RawContent(data=bg_data, box=BoxConstraints(width=W_f, height=H_f))

    style = TextStampStyle(
        stamp_text=stamp_text,
        timestamp_format='%Y.%m.%d %H:%M:%S UTC',
        background=background,
        background_opacity=1.0,
        background_layout=_bg_layout(),
        border_width=1,
        inner_content_layout=inner_layout,
        text_box_style=TextBoxStyle(font_size=font_dir),
    )
    # Assinar uma ou todas as páginas
    # Cada assinatura é incremental sobre o resultado da anterior
    pdf_atual = pdf_bytes

    for i, pagina_idx in enumerate(paginas_idx):
        sig_name = f'Assinatura_Digital_{pagina_idx}' if len(paginas_idx) > 1 else 'Assinatura_Digital'

        # Usar Y diferente para última página vs páginas intermediárias
        is_ultima = (pagina_idx == ultima_pagina_idx)
        y1  = y1_last  if is_ultima else y1_other
        y2  = y2_last  if is_ultima else y2_other
        W_f = x2 - x1
        H_f = y2 - y1

        sig_field = SigFieldSpec(
            sig_field_name=sig_name,
            on_page=pagina_idx,
            box=(x1, y1, x2, y2),
        )
        sig_meta = PdfSignatureMetadata(
            field_name=sig_name,
            reason=razao,
            location=local,
            name=cn,
        )

        pfx_tmp3 = tempfile.NamedTemporaryFile(suffix='.pfx', delete=False)
        pfx_tmp3.write(pfx_bytes)
        pfx_tmp3.close()
        try:
            signer3 = SimpleSigner.load_pkcs12(pfx_tmp3.name, passphrase=pfx_senha)
        finally:
            try: os.unlink(pfx_tmp3.name)
            except: pass

        pdf_signer = PdfSigner(sig_meta, signer3, stamp_style=style, new_field_spec=sig_field)
        pdf_in  = io.BytesIO(pdf_atual)
        pdf_out = io.BytesIO()
        pdf_signer.sign_pdf(IncrementalPdfFileWriter(pdf_in, strict=False), output=pdf_out)

        pdf_out.seek(0)
        pdf_atual = pdf_out.read()

    resultado = pdf_atual

    if resultado[:4] != b'%PDF':
        raise RuntimeError('Resultado da assinatura não é um PDF válido.')
    return resultado
