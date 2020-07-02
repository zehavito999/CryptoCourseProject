import registry
import secrets
import random

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

curve = registry.get_curve('brainpoolP256r1')

#using secret import (not accessible)(unable to print)
# side_a_private_key = secrets.randbelow(curve.field.n)
# print("side a private key:", compress(side_a_private_key))
# side_b_priavte_key = secrets.randbelow(curve.field.n)
# print("side b private key:", compress(side_b_priavte_key))

# using regular random(is accessible)(able to print)

#side_a_private_key = random.getrandbits(128)
side_a_private_key = random.randrange(1, curve.field.n)
print("side a private key:", hex(side_a_private_key))
#side_b_priavte_key = random.getrandbits(128)
side_b_private_key = random.randrange(1, curve.field.n)
print("side b private key:", hex(side_b_private_key))



side_a_public_key = side_a_private_key * curve.g
print("side a public key(R=a^g):", compress(side_a_public_key))

side_b_public_key = side_b_private_key * curve.g
print("side b public key(Q=b^g):", compress(side_b_public_key))

side_a_shared_key = side_a_private_key * side_b_public_key
print("side a shared key(Q^a):", compress(side_a_shared_key))

side_b_shared_key = side_b_priavte_key * side_a_public_key
print("side b shared key(R^b):", compress(side_b_shared_key))
compress(side_b_shared_key)
print("Equal shared keys:", side_a_shared_key == side_b_shared_key)