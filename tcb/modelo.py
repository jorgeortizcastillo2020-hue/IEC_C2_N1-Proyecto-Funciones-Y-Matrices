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
from decimal import Decimal, ROUND_FLOOR, getcontext

getcontext().prec = 60

MINUSCULAS = "abcdefghijklmnopqrstuvwxyz"
MAYUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITOS = "0123456789"
SIMBOLOS = "!@#$%&*?"
CLASES = [MINUSCULAS, MAYUSCULAS, DIGITOS, SIMBOLOS]
CHARSET = "".join(CLASES)  # 70 caracteres

LARGO_MIN_SALIDA = 16
LARGO_MAX_ENTRADA = 64
ESCALA_LOG = 10**4
MODULO_EXP = 5 * ESCALA_LOG
ESCALA_EXP = 10**6


class EntradaInvalida(ValueError):
    pass


def parametros(clave: bytes) -> dict:
    """Deriva los parámetros de las funciones a partir de la clave (la 'semilla').

    Cada coeficiente usa 4 bytes (32 bits) del HMAC, así el espacio de claves es enorme
    (> 2^100) y no solo unos pocos valores posibles.
    """
    h = hmac.new(clave, b"TCB-v1", hashlib.sha256).digest()
    grado = 1 + h[0] % 3
    # a, b, c, d: enteros de 32 bits (c y d >= 1 para que el polinomio sea siempre > 0)
    a, b, c, d = (1 + int.from_bytes(h[4 * i + 1: 4 * i + 5], "big") for i in range(4))
    if grado < 3:
        a = 0
    if grado < 2:
        b = 0
    k = int.from_bytes(h[17:21], "big")
    return {"grado": grado, "a": a, "b": b, "c": c, "d": d, "k": k, "s0": h[21] % 97}


def f_pol(x: int, p: dict) -> int:
    return p["a"] * x**3 + p["b"] * x**2 + p["c"] * x + p["d"]


def f_log(valor: int) -> int:
    if valor <= 0:  # control de dominio
        raise ValueError("El logaritmo exige un argumento > 0")
    return int((Decimal(valor).ln() * ESCALA_LOG).to_integral_value(ROUND_FLOOR))


def f_exp(L: int) -> tuple[Decimal, int]:
    v = Decimal(L % MODULO_EXP) / ESCALA_LOG
    w = int((v.exp() * ESCALA_EXP).to_integral_value(ROUND_FLOOR))
    return v, w


def validar(password: str) -> None:
    if not isinstance(password, str) or not password:
        raise EntradaInvalida("La contraseña no puede estar vacía.")
    if len(password) > LARGO_MAX_ENTRADA:
        raise EntradaInvalida(f"Máximo {LARGO_MAX_ENTRADA} caracteres.")


def trazar(password: str, clave: bytes) -> list[dict]:
    """Devuelve el detalle paso a paso (sirve para el informe y la demostración)."""
    validar(password)
    p = parametros(clave)
    n_out = max(len(password), LARGO_MIN_SALIDA)
    s = p["s0"]
    pasos = []
    for i in range(n_out):
        c = password[i % len(password)]
        x = ord(c) + (i + 1) + s
        pol = f_pol(x, p)
        L = f_log(pol)
        v, w = f_exp(L)
        alfabeto = CLASES[i] if i < 4 else CHARSET  # fuerza minúscula, mayúscula, dígito y símbolo
        y = alfabeto[(w + p["k"]) % len(alfabeto)]
        s = w % 97
        pasos.append({"i": i, "c": c, "x": x, "pol": pol, "log": L, "v": v, "exp": w, "y": y})
    return pasos


def transformar(password: str, clave: bytes) -> str:
    return "".join(paso["y"] for paso in trazar(password, clave))
