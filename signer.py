"""
Módulo de assinatura PDF usando pyhanko.
Gera campo de assinatura no padrão brasileiro (ICP-Brasil).
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


def carregar_certificado_base64(pfx_bytes: bytes, senha: bytes) -> dict:
    """Valida .pfx e retorna info pública. Lança ValueError se inválido."""
    try:
        key, cert, chain = load_key_and_certificates(pfx_bytes, senha)
    except Exception as e:
        raise ValueError(f'Certificado inválido ou senha incorreta: {e}')

    def get_attr(oid):
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except Exception:
            return ''

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

    # Extrair ND (Name Distinguished) do subject
    cn  = get_attr(NameOID.COMMON_NAME)
    org = get_attr(NameOID.ORGANIZATION_NAME)
    ou  = get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME)
    c   = get_attr(NameOID.COUNTRY_NAME)

    return {
        'titular':     cn,
        'organizacao': org,
        'ou':          ou,
        'pais':        c,
        'valido_de':   valid_from.strftime('%d/%m/%Y'),
        'valido_ate':  valid_until.strftime('%d/%m/%Y'),
        'serial':      str(cert.serial_number),
        'expirado':    False,
    }


def _montar_nd(cert) -> str:
    """Monta a string ND (Name Distinguished) no padrão ICP-Brasil."""
    def get_attr(oid):
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except Exception:
            return ''
    partes = []
    c  = get_attr(NameOID.COUNTRY_NAME)
    o  = get_attr(NameOID.ORGANIZATION_NAME)
    ou = get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME)
    cn = get_attr(NameOID.COMMON_NAME)
    if c:  partes.append(f'C={c}')
    if o:  partes.append(f'O={o}')
    if ou: partes.append(f'OU={ou}')
    if cn: partes.append(f'CN={cn}')
    return ', '.join(partes) if partes else cn


def assinar_pdf(
    pdf_bytes: bytes,
    pfx_bytes: bytes,
    pfx_senha: bytes,
    config:    dict,
) -> bytes:
    """
    Assina PDF com aparência no padrão brasileiro ICP-Brasil.
    """
    # Carregar signer
    pfx_tmp = tempfile.NamedTemporaryFile(suffix='.pfx', delete=False)
    pfx_tmp.write(pfx_bytes)
    pfx_tmp.close()
    try:
        signer = SimpleSigner.load_pkcs12(pfx_tmp.name, passphrase=pfx_senha)
    except Exception as e:
        os.unlink(pfx_tmp.name)
        raise ValueError(f'Erro ao carregar certificado: {e}')
    finally:
        try:
            os.unlink(pfx_tmp.name)
        except Exception:
            pass

    # Info do certificado
    try:
        _, cert, _ = load_key_and_certificates(pfx_bytes, pfx_senha)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        nd = _montar_nd(cert)
    except Exception:
        cn = 'Assinante'
        nd = ''

    # Config
    MM     = 2.834645
    x1     = config.get('x1_mm',  8.0) * MM
    y1     = config.get('y1_mm',  5.0) * MM
    x2     = config.get('x2_mm', 91.0) * MM
    y2     = config.get('y2_mm', 18.0) * MM
    razao  = config.get('razao', 'Eu sou o autor deste documento')
    local  = config.get('local', 'Brasil')
    pagina = int(config.get('pagina', -1))

    # Número de páginas
    with io.BytesIO(pdf_bytes) as fbuf:
        reader    = PdfFileReader(fbuf)
        n_paginas = int(reader.root['/Pages'].get_object()['/Count'])

    if pagina < 0:
        pagina_idx = max(0, n_paginas + pagina)
    else:
        pagina_idx = min(pagina, n_paginas - 1)

    # ── Aparência no padrão ICP-Brasil / Foxit ─────────────────────────────
    # Replicar o visual da imagem de referência:
    # "Assinado digitalmente por NOME
    #  ND: C=BR, O=ICP-Brasil, OU=..., CN=...
    #  Razão: ...
    #  Localização: ...
    #  Data: YYYY.MM.DD HH:MM:SS UTC"

    stamp_text = (
        "Assinado digitalmente por %(signer)s\n"
        f"ND: {nd}\n"
        f"Razao: {razao}\n"
        f"Localizacao: {local}\n"
        "Data: %(ts)s"
    )

    stamp_style = TextStampStyle(
        stamp_text=stamp_text,
        timestamp_format='%Y.%m.%d %H:%M:%S UTC',
        background_opacity=0.0,   # fundo transparente
        border_width=1,
    )
    # ───────────────────────────────────────────────────────────────────────

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

    pdf_signer = PdfSigner(sig_meta, signer, stamp_style=stamp_style, new_field_spec=sig_field)

    pdf_in  = io.BytesIO(pdf_bytes)
    pdf_out = io.BytesIO()
    w       = IncrementalPdfFileWriter(pdf_in)
    pdf_signer.sign_pdf(w, output=pdf_out)

    pdf_out.seek(0)
    resultado = pdf_out.read()

    if resultado[:4] != b'%PDF':
        raise RuntimeError('Resultado da assinatura não é um PDF válido')

    return resultado
