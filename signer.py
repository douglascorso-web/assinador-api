"""
Módulo de assinatura PDF usando pyhanko.
Suporta qualquer PDF, incluindo os com XRef stream comprimido (PDF 1.5+).
"""

import io
import os
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import NameOID

from pyhanko.sign.signers import SimpleSigner, PdfSignatureMetadata, sign_pdf
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec


def carregar_certificado_base64(pfx_bytes: bytes, senha: bytes) -> dict:
    """
    Valida um .pfx e retorna informações públicas do certificado.
    Lança ValueError se inválido ou senha incorreta.
    """
    try:
        key, cert, chain = load_key_and_certificates(pfx_bytes, senha)
    except Exception as e:
        raise ValueError(f'Certificado inválido ou senha incorreta: {e}')

    def get_attr(oid):
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except Exception:
            return ''

    # Compatibilidade Python 3.9/3.10/3.11+
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
        'titular':     get_attr(NameOID.COMMON_NAME),
        'organizacao': get_attr(NameOID.ORGANIZATION_NAME),
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
    """
    Assina um PDF digitalmente usando pyhanko.

    Args:
        pdf_bytes : bytes do PDF original
        pfx_bytes : bytes do certificado .pfx
        pfx_senha : senha do certificado (bytes)
        config    : dict com:
                      pagina  : -1=última, 0=primeira
                      x1_mm, y1_mm, x2_mm, y2_mm : posição em mm
                      razao, local : metadados da assinatura

    Returns: bytes do PDF assinado
    """
    # Salvar .pfx em arquivo temporário (pyhanko exige path)
    pfx_tmp = tempfile.NamedTemporaryFile(suffix='.pfx', delete=False)
    pfx_tmp.write(pfx_bytes)
    pfx_tmp.close()

    try:
        signer = SimpleSigner.load_pkcs12(pfx_tmp.name, passphrase=pfx_senha)
    except Exception as e:
        os.unlink(pfx_tmp.name)
        raise ValueError(f'Erro ao carregar certificado: {e}')
    finally:
        # Apagar imediatamente após carregar (segurança)
        try:
            os.unlink(pfx_tmp.name)
        except Exception:
            pass

    # Nome do titular para metadados
    try:
        _, cert, _ = load_key_and_certificates(pfx_bytes, pfx_senha)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = 'Assinante'

    # Posição do campo em pontos PDF (1mm = 2.834645pt)
    MM = 2.834645
    x1 = config.get('x1_mm',  8.0) * MM
    y1 = config.get('y1_mm',  5.0) * MM
    x2 = config.get('x2_mm', 91.0) * MM
    y2 = config.get('y2_mm', 12.0) * MM

    razao  = config.get('razao', 'Eu sou o autor deste documento')
    local  = config.get('local', 'Brasil')
    pagina = int(config.get('pagina', -1))

    # Determinar índice da página (0-based)
    with io.BytesIO(pdf_bytes) as fbuf:
        reader    = PdfFileReader(fbuf)
        n_paginas = int(reader.root["/Pages"].get_object()["/Count"])

    if pagina < 0:
        pagina_idx = max(0, n_paginas + pagina)
    else:
        pagina_idx = min(pagina, n_paginas - 1)

    # Campo e metadados
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

    # Assinar
    pdf_in  = io.BytesIO(pdf_bytes)
    pdf_out = io.BytesIO()

    writer = IncrementalPdfFileWriter(pdf_in)
    sign_pdf(writer, sig_meta, signer=signer, new_field_spec=sig_field, output=pdf_out)

    pdf_out.seek(0)
    resultado = pdf_out.read()

    if resultado[:4] != b'%PDF':
        raise RuntimeError('Resultado da assinatura não é um PDF válido')

    return resultado
