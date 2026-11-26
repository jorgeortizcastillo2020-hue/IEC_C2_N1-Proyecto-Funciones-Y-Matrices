import pytest
from modelo import (CHARSET, LARGO_MAX_ENTRADA, LARGO_MIN_SALIDA, EntradaInvalida,
                    f_log, parametros, transformar, trazar, CLASES)

K1, K2 = b"clave-empresa-A", b"clave-empresa-B"


def test_determinismo():  # pregunta 1
    assert transformar("contraseña123", K1) == transformar("contraseña123", K1)


def test_distinta_semilla_distinta_salida():
    assert transformar("contraseña123", K1) != transformar("contraseña123", K2)


def test_distinta_entrada_distinta_salida():
    assert transformar("contraseña123", K1) != transformar("contraseña124", K1)


def test_salida_en_charset_y_largo():
    r = transformar("abc", K1)
    assert len(r) == LARGO_MIN_SALIDA and all(ch in CHARSET for ch in r)
    assert len(transformar("x" * 40, K1)) == 40


def test_politica_de_complejidad():
    r = transformar("hola", K1)
    assert all(r[i] in CLASES[i] for i in range(4))


def test_difusion():  # cambiar el 1er carácter altera el resto
    a, b = transformar("aontraseña123", K1), transformar("bontraseña123", K1)
    assert sum(x != y for x, y in zip(a, b)) > 8


@pytest.mark.parametrize("malo", ["", None, "x" * (LARGO_MAX_ENTRADA + 1)])
def test_entrada_invalida(malo):
    with pytest.raises(EntradaInvalida):
        transformar(malo, K1)


def test_dominio_logaritmo():
    for paso in trazar("a", K1) + trazar("~" * 64, K2):
        assert paso["pol"] > 0
    with pytest.raises(ValueError):
        f_log(0)


def test_parametros_en_rango():
    for i in range(200):
        p = parametros(str(i).encode())
        assert p["grado"] in (1, 2, 3) and p["c"] >= 1 and p["d"] >= 1


def test_espacio_de_claves_amplio():
    # Los coeficientes ya no se limitan a 1..9: con muchas claves hay muchos valores distintos.
    cs = {parametros(str(i).encode())["c"] for i in range(200)}
    assert len(cs) > 150 and max(cs) > 10**6


def test_api():
    from app import app
    c = app.test_client()
    ok = c.post("/transformar", json={"password": "contraseña123"})
    assert ok.status_code == 200 and len(ok.get_json()["resultado"]) == LARGO_MIN_SALIDA
    assert c.post("/transformar", json={"password": ""}).status_code == 400
    assert c.post("/transformar", data="no json").status_code == 400
