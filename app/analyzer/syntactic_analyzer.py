# me llega un arreglo de 2 string, el primer string con el header y el seguindo array de string el payload (devuelto por el decoder)
# verficio un JSON valido y devuelvo un diccionario con los datos del payload.
# hago una validacion de estructuras 


# -*- coding: utf-8 -*-
"""
ANALIZADOR SINTÁCTICO (PROYECTO JWT)
-----------------------------------------------------------
Incluye:
- Parser JSON manual (parcial) basado en la GLC.
- Fallback a json.loads por si no funciona el parser manual.
- Validaciones estructurales del header y payload.
- typ != "JWT" tratado como error fatal.
"""

import json

class JSONParseError(Exception):
    pass

class JSONParser:
    def __init__(self, text):
        self.text = text
        self.i = 0

    def skip_ws(self):
        while self.i < len(self.text) and self.text[self.i] in " \n\t\r":
            self.i += 1

    def peek(self):
        self.skip_ws()
        if self.i < len(self.text):
            return self.text[self.i]
        return None

    def parse(self):
        value = self.parse_value()
        self.skip_ws()
        if self.i != len(self.text):
            raise JSONParseError("Texto extra después del JSON.")
        return value

    def parse_value(self):
        self.skip_ws()
        c = self.peek()
        if c is None:
            raise JSONParseError("EOF inesperado.")
        if c == '"': return self.parse_string()
        if c == '{': return self.parse_object()
        if c == '[': return self.parse_array()
        if c.isdigit() or c == '-': return self.parse_number()
        if self.text.startswith("true", self.i):
            self.i += 4
            return True
        if self.text.startswith("false", self.i):
            self.i += 5
            return False
        if self.text.startswith("null", self.i):
            self.i += 4
            return None
        raise JSONParseError("Token inesperado en value: " + c)

    def parse_string(self):
        self.skip_ws()
        if self.peek() != '"':
            raise JSONParseError("Se esperaba inicio de string.")
        self.i += 1
        out = ""
        while self.i < len(self.text):
            c = self.text[self.i]
            if c == '"':
                self.i += 1
                return out
            if c == '\\':
                if self.i + 1 >= len(self.text):
                    raise JSONParseError("Escape incompleto.")
                nxt = self.text[self.i+1]
                if nxt in ['"', '\\', '/']:
                    out += nxt
                    self.i += 2
                elif nxt == 'n':
                    out += '\n'; self.i += 2
                elif nxt == 't':
                    out += '\t'; self.i += 2
                elif nxt == 'r':
                    out += '\r'; self.i += 2
                elif nxt == 'u':
                    hexv = self.text[self.i+2:self.i+6]
                    if len(hexv) < 4:
                        raise JSONParseError("Unicode incompleto.")
                    out += chr(int(hexv, 16))
                    self.i += 6
                else:
                    raise JSONParseError("Escape inválido.")
            else:
                out += c; self.i += 1
        raise JSONParseError("String no cerrado.")

    def parse_number(self):
        self.skip_ws()
        start = self.i
        if self.peek() == '-': self.i += 1
        if not self.peek() or not self.peek().isdigit():
            raise JSONParseError("Número inválido.")
        while self.peek() and self.peek().isdigit():
            self.i += 1
        if self.peek() == '.':
            self.i += 1
            if not self.peek() or not self.peek().isdigit():
                raise JSONParseError("Decimal inválido.")
            while self.peek() and self.peek().isdigit():
                self.i += 1
        num_str = self.text[start:self.i]
        try:
            if '.' in num_str:
                return float(num_str)
            return int(num_str)
        except:
            raise JSONParseError("Número mal formado.")

    def parse_object(self):
        self.skip_ws()
        if self.peek() != '{': raise JSONParseError("Se esperaba '{'.")
        self.i += 1
        obj = {}
        self.skip_ws()
        if self.peek() == '}':
            self.i += 1
            return obj
        while True:
            key = self.parse_string()
            self.skip_ws()
            if self.peek() != ':': raise JSONParseError("Se esperaba ':'.")
            self.i += 1
            val = self.parse_value()
            obj[key] = val
            self.skip_ws()
            if self.peek() == '}':
                self.i += 1
                break
            if self.peek() != ',': raise JSONParseError("Se esperaba ',' o '}'.")
            self.i += 1
        return obj

    def parse_array(self):
        self.skip_ws()
        if self.peek() != '[': raise JSONParseError("Se esperaba '['.")
        self.i += 1
        arr = []
        self.skip_ws()
        if self.peek() == ']':
            self.i += 1
            return arr
        while True:
            arr.append(self.parse_value())
            self.skip_ws()
            if self.peek() == ']':
                self.i += 1
                break
            if self.peek() != ',': raise JSONParseError("Se esperaba ',' o ']'.")
            self.i += 1
        return arr


def parse_json_manual(text):
    return JSONParser(text).parse()


def analyze_syntax(header_str, payload_str):
    result = {"success": True, "valid": False, "header": None, "payload": None, "errors": []}

    # PARSE HEADER
    try:
        try: header = parse_json_manual(header_str)
        except: header = json.loads(header_str)
    except Exception as e:
        result["errors"].append("Header inválido: " + str(e))
        return result

    # PARSE PAYLOAD
    try:
        try: payload = parse_json_manual(payload_str)
        except: payload = json.loads(payload_str)
    except Exception as e:
        result["errors"].append("Payload inválido: " + str(e))
        return result

    result["header"] = header
    result["payload"] = payload

    # VALIDACIONES
    if not isinstance(header, dict):
        result["errors"].append("Header debe ser objeto JSON.")
    if not isinstance(payload, dict):
        result["errors"].append("Payload debe ser objeto JSON.")

    if "alg" not in header:
        result["errors"].append("Header faltante 'alg'.")
    if "typ" not in header:
        result["errors"].append("Header faltante 'typ'.")
    else:
        if header["typ"] != "JWT":
            result["errors"].append("Header 'typ' debe ser exactamente 'JWT' (FATAL).")

    for t in ("iat", "exp", "nbf"):
        if t in payload and not isinstance(payload[t], int):
            result["errors"].append(f"Claim '{t}' debe ser entero.")

    if "aud" in payload:
        aud = payload["aud"]
        if isinstance(aud, list):
            if not all(isinstance(x, str) for x in aud):
                result["errors"].append("Claim 'aud' debe ser lista de strings.")
        elif not isinstance(aud, str):
            result["errors"].append("Claim 'aud' debe ser string o lista.")

    if "permissions" in payload:
        perms = payload["permissions"]
        if not (isinstance(perms, list) and all(isinstance(p, str) for p in perms)):
            result["errors"].append("Claim 'permissions' debe ser lista de strings.")

    if not result["errors"]:
        result["valid"] = True

    return result
