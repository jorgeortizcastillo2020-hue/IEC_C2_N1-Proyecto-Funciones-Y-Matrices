"""
Modelo matemático del proyecto "El TCB".

Cadena de transformación, por cada carácter c_i de la contraseña (i = 0, 1, 2, ...):

    x_i = ord(c_i) + (i + 1) + s_(i-1)          (entrada; s_(-1) viene de la semilla)
    p_i = f_pol(x_i) = a·x³ + b·x² + c·x + d    (polinomio de grado g = 1, 2 o 3)
    L_i = floor( 10⁴ · ln(p_i) )                (logarítmica; p_i >= 1 > 0, dominio garantizado)
    v_i = (L_i mod 50000) / 10⁴                 (acota el exponente al intervalo [0, 5) )
    w_i = floor( 10⁶ · e^(v_i) )                (exponencial; w_i <= ~1.5·10⁸, sin desbordes)
    y_i = alfabeto_i[ (w_i + k) mod |alfabeto_i| ]
    s_i = w_i mod 97                            (se arrastra al siguiente carácter: difusión)

Los parámetros (g, a, b, c, d, k, s_-1) salen de HMAC-SHA256(clave, "TCB-v1"): la "semilla".
Los coeficientes son enteros de 32 bits, lo que da un espacio de claves de más de 100 bits.
Se usa `decimal` (precisión fija) para que ln y exp den el mismo resultado en cualquier equipo.
No se guarda nada: la función solo calcula y devuelve.
"""
import hashlib
import hmac
import math
from decimal import Decimal, ROUND_FLOOR, getcontext

# `decimal` calcula con precisión fija (60 dígitos): ln y exp dan lo mismo en cualquier computador.
getcontext().prec = 60

# ---------------------------------------------------------------------------
# CONSTANTES: alfabeto de salida y límites
# ---------------------------------------------------------------------------
MINUSCULAS = "abcdefghijklmnopqrstuvwxyz"
MAYUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITOS = "0123456789"
SIMBOLOS = "!@#$%&*?"
CLASES = [MINUSCULAS, MAYUSCULAS, DIGITOS, SIMBOLOS]
CHARSET = "".join(CLASES)  # 70 caracteres posibles en la contraseña nueva

LARGO_MIN_SALIDA = 16   # la contraseña nueva mide al menos 16 caracteres
LARGO_MAX_ENTRADA = 64  # límite de largo de la contraseña original
ESCALA_LOG = 10**4      # ln(p) se multiplica por 10⁴ y se trunca: L = ⌊10⁴·ln p⌋
MODULO_EXP = 5 * ESCALA_LOG  # L mod 50000 -> el exponente v queda en [0, 5)
ESCALA_EXP = 10**6      # e^v se multiplica por 10⁶ y se trunca: w = ⌊10⁶·e^v⌋


class EntradaInvalida(ValueError):
    """Se lanza cuando la contraseña está vacía o es demasiado larga."""


# ---------------------------------------------------------------------------
# SEMILLA: de la clave de la empresa salen los parámetros de las funciones
# ---------------------------------------------------------------------------
def parametros(clave: bytes) -> dict:
    """Deriva los parámetros de las funciones a partir de la clave (la 'semilla').

    Cada coeficiente usa 4 bytes (32 bits) del HMAC, así el espacio de claves es enorme
    (> 2^100) y no solo unos pocos valores posibles.
    """
    # HMAC-SHA256: misma clave -> mismos 32 bytes (determinismo); otra clave -> otros bytes
    h = hmac.new(clave, b"TCB-v1", hashlib.sha256).digest()
    grado = 1 + h[0] % 3  # grado del polinomio: 1, 2 o 3
    # a, b, c, d: enteros de 32 bits (c y d >= 1 para que el polinomio sea siempre > 0)
    a, b, c, d = (1 + int.from_bytes(h[4 * i + 1: 4 * i + 5], "big") for i in range(4))
    if grado < 3:
        a = 0  # sin término cúbico
    if grado < 2:
        b = 0  # sin término cuadrático
    k = int.from_bytes(h[17:21], "big")  # desplazamiento final al elegir el carácter
    return {"grado": grado, "a": a, "b": b, "c": c, "d": d, "k": k, "s0": h[21] % 97}


# ---------------------------------------------------------------------------
# FUNCIÓN 1 · POLINÓMICA:  f_pol(x) = a·x³ + b·x² + c·x + d   (grado 1, 2 o 3)
# ---------------------------------------------------------------------------
def f_pol(x: int, p: dict) -> int:
    """Evalúa el polinomio. Como c y d >= 1 y x >= 1, el resultado siempre es > 0."""
    return p["a"] * x**3 + p["b"] * x**2 + p["c"] * x + p["d"]


# ---------------------------------------------------------------------------
# FUNCIÓN 2 · LOGARÍTMICA:  L = ⌊10⁴ · ln(p)⌋   (dominio: p > 0)
# ---------------------------------------------------------------------------
def f_log(valor: int) -> int:
    """Logaritmo natural escalado y truncado a entero."""
    if valor <= 0:  # CONTROL DE DOMINIO: ln solo existe para valores > 0
        raise ValueError("El logaritmo exige un argumento > 0")
    return int((Decimal(valor).ln() * ESCALA_LOG).to_integral_value(ROUND_FLOOR))


# ---------------------------------------------------------------------------
# FUNCIÓN 3 · EXPONENCIAL:  w = ⌊10⁶ · e^v⌋   con v = (L mod 50000) / 10⁴ en [0, 5)
# ---------------------------------------------------------------------------
def f_exp(L: int) -> tuple[Decimal, int]:
    """Exponencial con exponente acotado.

    El módulo es clave: sin él, e^(ln p) = p y el logaritmo y la exponencial
    (que son inversas) se anularían. Además evita que e^v crezca sin límite.
    """
    v = Decimal(L % MODULO_EXP) / ESCALA_LOG  # exponente acotado a [0, 5)
    w = int((v.exp() * ESCALA_EXP).to_integral_value(ROUND_FLOOR))
    return v, w


def validar(password: str) -> None:
    """Rechaza contraseñas vacías o demasiado largas."""
    if not isinstance(password, str) or not password:
        raise EntradaInvalida("La contraseña no puede estar vacía.")
    if len(password) > LARGO_MAX_ENTRADA:
        raise EntradaInvalida(f"Máximo {LARGO_MAX_ENTRADA} caracteres.")


# ---------------------------------------------------------------------------
# CADENA COMPLETA: carácter -> polinomio -> logaritmo -> exponencial -> carácter nuevo
# ---------------------------------------------------------------------------
def trazar(password: str, clave: bytes) -> list[dict]:
    """Devuelve el detalle paso a paso (sirve para el informe y la demostración)."""
    validar(password)
    p = parametros(clave)
    n_out = max(len(password), LARGO_MIN_SALIDA)  # si es corta, se recicla hasta 16
    s = p["s0"]  # estado que se arrastra de un carácter al siguiente (sucesión recursiva)
    pasos = []
    for i in range(n_out):
        c = password[i % len(password)]
        x = ord(c) + (i + 1) + s            # 1) entrada: código + posición + estado anterior
        pol = f_pol(x, p)                   # 2) polinómica
        L = f_log(pol)                      # 3) logarítmica (pol > 0 garantizado)
        v, w = f_exp(L)                     # 4) exponencial con exponente acotado
        # 5) elige el carácter nuevo; los 4 primeros fuerzan minúscula, mayúscula, dígito y símbolo
        alfabeto = CLASES[i] if i < 4 else CHARSET
        y = alfabeto[(w + p["k"]) % len(alfabeto)]
        s = w % 97                          # 6) nuevo estado: así un cambio se propaga al resto
        pasos.append({"i": i, "c": c, "x": x, "pol": pol, "log": L, "v": v, "exp": w, "y": y})
    return pasos


def transformar(password: str, clave: bytes) -> str:
    """Contraseña original -> contraseña robustecida (no guarda nada)."""
    return "".join(paso["y"] for paso in trazar(password, clave))


# ---------------------------------------------------------------------------
# SOLO PARA GRAFICAR: puntos de las curvas que se dibujan en la página
# (usa float porque solo es para el dibujo; el cálculo real usa `decimal`)
# ---------------------------------------------------------------------------
def curvas(p: dict, pasos: list[dict], n: int = 60) -> dict:
    """Puntos de f_pol, ln y exp para dibujarlas junto a los puntos reales de la ejecución."""
    x_max = max(paso["x"] for paso in pasos) * 1.15
    pol = [[x_max * j / n, float(f_pol(x_max * j / n, p))] for j in range(n + 1)]
    p_max = max(paso["pol"] for paso in pasos) * 2
    # p va de 1 hasta p_max en escala geométrica (ln solo existe para p > 0)
    ps = [10 ** (math.log10(p_max) * j / n) for j in range(n + 1)]
    ln = [[q, math.log(q)] for q in ps]
    exp = [[5 * j / n, math.exp(5 * j / n)] for j in range(n + 1)]
    return {"pol": pol, "ln": ln, "exp": exp}
