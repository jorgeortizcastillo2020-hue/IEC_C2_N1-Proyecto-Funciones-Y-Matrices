"""API local del TCB. Uso: TCB_CLAVE="tu-clave" python app.py  ->  http://127.0.0.1:5000"""
import os
from flask import Flask, jsonify, render_template, request
from modelo import EntradaInvalida, transformar

app = Flask(__name__)

_clave = os.environ.get("TCB_CLAVE")
if not _clave:
    print("AVISO: usando clave de demostración. Define TCB_CLAVE para uso real.")
    _clave = "clave-demo-no-usar-en-produccion"
CLAVE = _clave.encode()


@app.get("/")
def inicio():
    return render_template("index.html")


@app.post("/transformar")
def api_transformar():
    datos = request.get_json(silent=True) or {}
    try:
        # La contraseña solo vive en memoria durante esta llamada: no se guarda ni se registra.
        return jsonify(resultado=transformar(datos.get("password"), CLAVE))
    except EntradaInvalida as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
