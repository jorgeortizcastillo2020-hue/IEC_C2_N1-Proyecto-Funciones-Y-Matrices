"""API local del TCB. Uso: TCB_CLAVE="tu-clave" python app.py  ->  http://127.0.0.1:5000"""
import os
from flask import Flask, jsonify, render_template, request
from modelo import EntradaInvalida, curvas, parametros, trazar, transformar

app = Flask(__name__)

# La clave de la empresa (la "semilla") se lee de una variable de entorno, no del código.
_clave = os.environ.get("TCB_CLAVE")
if not _clave:
    print("AVISO: usando clave de demostración. Define TCB_CLAVE para uso real.")
    _clave = "clave-demo-no-usar-en-produccion"
CLAVE = _clave.encode()

PASOS_EXPLICACION = 6  # cuántos caracteres se detallan en la sección "cómo funciona"


@app.get("/")
def inicio():
    """Entrega la página (templates/index.html)."""
    return render_template("index.html")


@app.post("/transformar")
def api_transformar():
    """Recibe {"password": "..."} y devuelve {"resultado": "..."}."""
    datos = request.get_json(silent=True) or {}
    try:
        # La contraseña solo vive en memoria durante esta llamada: no se guarda ni se registra.
        return jsonify(resultado=transformar(datos.get("password"), CLAVE))
    except EntradaInvalida as e:
        return jsonify(error=str(e)), 400


@app.post("/explicar")
def api_explicar():
    """Devuelve la semilla, el paso a paso y los puntos de las curvas (para la sección didáctica)."""
    datos = request.get_json(silent=True) or {}
    try:
        pasos = trazar(datos.get("password"), CLAVE)
    except EntradaInvalida as e:
        return jsonify(error=str(e)), 400
    total = len(pasos)
    pasos = pasos[:PASOS_EXPLICACION]
    p = parametros(CLAVE)
    return jsonify(
        semilla=p,
        total=total,
        # los números grandes viajan como texto para que JavaScript no pierda precisión
        pasos=[{**paso, "pol": str(paso["pol"]), "exp": str(paso["exp"]), "v": str(paso["v"])}
               for paso in pasos],
        curvas=curvas(p, pasos),
    )


if __name__ == "__main__":
    # Solo escucha en este computador (127.0.0.1): no es accesible desde la red.
    app.run(host="127.0.0.1", port=5000, debug=False)
