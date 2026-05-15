"""
Microserviço de Assinatura Digital de PDFs
Recebe PDFs via POST, assina com pyhanko + certificado A1, devolve PDF assinado.
"""

import os
import io
import json
import base64
import logging
import tempfile
from datetime import datetime

from flask import Flask, request, jsonify, send_file
from functools import wraps

from signer import assinar_pdf, carregar_certificado_base64

# ─── Configuração ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# Chave de API obrigatória para autenticar as requisições do WordPress
API_KEY = os.environ.get('API_KEY', '')

# Certificado e senha podem vir por variável de ambiente (base64 do .pfx)
# ou ser enviados a cada requisição
PFX_B64   = os.environ.get('PFX_BASE64', '')
PFX_SENHA = os.environ.get('PFX_SENHA', '')


# ─── Autenticação ─────────────────────────────────────────────────────────────

def requer_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.form.get('api_key')
        if API_KEY and key != API_KEY:
            log.warning(f"Tentativa com API key inválida de {request.remote_addr}")
            return jsonify({'erro': 'API key inválida'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Verificação de saúde — WordPress usa para testar conexão."""
    return jsonify({
        'status': 'ok',
        'servico': 'Assinador PDF',
        'versao': '1.0.0',
        'certificado_configurado': bool(PFX_B64),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/assinar', methods=['POST'])
@requer_api_key
def assinar():
    """
    Assina um PDF digitalmente.

    Aceita multipart/form-data com:
      - pdf         : arquivo PDF (required)
      - config      : JSON com configurações do selo (optional)
      - pfx_base64  : certificado .pfx em base64 (optional, usa env se omitido)
      - pfx_senha   : senha do certificado (optional, usa env se omitido)

    Retorna o PDF assinado como application/pdf,
    ou JSON com erro em caso de falha.
    """
    # 1. Receber PDF
    if 'pdf' not in request.files:
        return jsonify({'erro': 'Nenhum arquivo PDF enviado (campo: pdf)'}), 400

    pdf_file = request.files['pdf']
    if not pdf_file.filename.lower().endswith('.pdf'):
        return jsonify({'erro': 'O arquivo enviado não é um PDF'}), 400

    pdf_bytes = pdf_file.read()
    if len(pdf_bytes) < 10 or pdf_bytes[:4] != b'%PDF':
        return jsonify({'erro': 'Arquivo inválido: não é um PDF'}), 400

    # 2. Certificado: prioridade → enviado na requisição → variável de ambiente
    pfx_b64   = request.form.get('pfx_base64') or PFX_B64
    pfx_senha = request.form.get('pfx_senha')  or PFX_SENHA

    if not pfx_b64:
        return jsonify({'erro': 'Nenhum certificado configurado. Envie pfx_base64 ou defina PFX_BASE64 no ambiente.'}), 400
    if not pfx_senha:
        return jsonify({'erro': 'Senha do certificado não informada.'}), 400

    # 3. Configurações do selo
    config_str = request.form.get('config', '{}')
    try:
        config = json.loads(config_str)
    except Exception:
        config = {}

    config.setdefault('razao',   'Eu sou o autor deste documento')
    config.setdefault('local',   'Brasil')
    config.setdefault('pagina',  -1)     # -1 = última
    config.setdefault('x1_mm',   8.0)
    config.setdefault('y1_mm',   5.0)
    config.setdefault('x2_mm',  91.0)
    config.setdefault('y2_mm',  18.0)

    # 4. Assinar
    try:
        pfx_bytes = base64.b64decode(pfx_b64)
        resultado = assinar_pdf(
            pdf_bytes    = pdf_bytes,
            pfx_bytes    = pfx_bytes,
            pfx_senha    = pfx_senha.encode(),
            config       = config,
        )
    except ValueError as e:
        log.error(f"Erro de validação: {e}")
        return jsonify({'erro': str(e)}), 422
    except Exception as e:
        log.exception("Erro ao assinar PDF")
        return jsonify({'erro': f'Erro interno ao assinar: {str(e)}'}), 500

    # 5. Retornar PDF assinado
    nome_original = pdf_file.filename.replace('.pdf', '')
    nome_saida    = f"{nome_original}_assinado.pdf"

    log.info(f"PDF assinado com sucesso: {nome_saida} ({len(resultado)} bytes)")

    return send_file(
        io.BytesIO(resultado),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=nome_saida
    )


@app.route('/configurar-certificado', methods=['POST'])
@requer_api_key
def configurar_certificado():
    """
    Testa se um certificado .pfx é válido.
    Útil para validar antes de salvar no WordPress.

    Aceita multipart/form-data:
      - pfx_file : arquivo .pfx
      - pfx_senha: senha
    """
    if 'pfx_file' not in request.files:
        return jsonify({'erro': 'Envie o arquivo .pfx no campo pfx_file'}), 400

    pfx_bytes = request.files['pfx_file'].read()
    senha     = request.form.get('pfx_senha', '').encode()

    try:
        info = carregar_certificado_base64(pfx_bytes, senha)
        return jsonify({'ok': True, 'info': info})
    except Exception as e:
        return jsonify({'ok': False, 'erro': str(e)}), 422


# ─── Inicialização ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    log.info(f"Iniciando Assinador PDF na porta {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
