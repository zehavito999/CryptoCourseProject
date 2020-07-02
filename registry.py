# -*- coding: utf-8 -*-

import ec as ec


EC_CURVE_REGISTRY = {"brainpoolP256r1": {# Field characteristic.
                                         "p": 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
                                         # Curve coefficients.
                                         "a": 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
                                         "b": 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
                                         # Base point.
                                         "g": (0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
                                               0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997),
                                         # Subgroup order.
                                         "n": 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
                                         # Subgroup cofactor.
                                         "h": 0x1},
                     "secp256r1": {"p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                                   "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                                   "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                                   "g": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
                                   "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                                   "h": 0x1}
}


def get_curve(name):
    """

    :param name: name of the curve
    :return: curve
    """
    curve_params = {}
    for k, v in EC_CURVE_REGISTRY.items():
        if name.lower() == k.lower():
            curve_params = v
    if curve_params == {}:
        raise ValueError("Unknown elliptic curve name")
    try:
        sub_group = ec.SubGroup(curve_params["p"], curve_params["g"], curve_params["n"], curve_params["h"])#value of the field
        curve = ec.Curve(curve_params["a"], curve_params["b"], sub_group, name)#value of the curve
    except KeyError:
        raise RuntimeError("Missing parameters for curve %s" % name)
    return curve
