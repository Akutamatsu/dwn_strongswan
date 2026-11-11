import operator as op
from math import factorial as fac
from math import sqrt, log
import sys
from proba_util import *

class KyberParameterSet:
    def __init__(self, n, m, ks, ke,  q, rqk, rqc, rq2, ke_ct=None):
        if ke_ct is None:
            ke_ct = ke
        self.n = n
        self.m = m
        self.ks = ks     # binary distribution for the secret key
        self.ke = ke    # binary distribution for the ciphertext errors
        self.ke_ct = ke_ct    # binary distribution for the ciphertext errors
        self.q = q
        self.rqk = rqk  # 2^(bits in the public key)
        self.rqc = rqc  # 2^(bits in the first ciphertext)
        self.rq2 = rq2  # 2^(bits in the second ciphertext)

def p2_cyclotomic_final_error_distribution(ps):
    """ construct the final error distribution in our encryption scheme
    :param ps: parameter set (ParameterSet)
    """
    chis = build_centered_binomial_law(ps.ks)           # LWE error law for the key
    chie = build_centered_binomial_law(ps.ke_ct)        # LWE error law for the ciphertext
    chie_pk = build_centered_binomial_law(ps.ke)
    Rk = build_mod_switching_error_law(ps.q, ps.rqk)    # Rounding error public key
    Rc = build_mod_switching_error_law(ps.q, ps.rqc)    # rounding error first ciphertext
    chiRs = law_convolution(chis, Rk)                   # LWE+Rounding error key
    chiRe = law_convolution(chie, Rc)                   # LWE + rounding error ciphertext

    B1 = law_product(chie_pk, chiRs)                       # (LWE+Rounding error) * LWE (as in a E*S product)
    B2 = law_product(chis, chiRe)

    C1 = iter_law_convolution(B1, ps.m * ps.n)
    C2 = iter_law_convolution(B2, ps.m * ps.n)

    C=law_convolution(C1, C2)

    R2 = build_mod_switching_error_law(ps.q, ps.rq2)    # Rounding2 (in the ciphertext mask part)
    F = law_convolution(R2, chie)                       # LWE+Rounding2 error
    D = law_convolution(C, F)                           # Final error
    return D


def p2_cyclotomic_error_probability(ps):
    F = p2_cyclotomic_final_error_distribution(ps)
    proba = tail_probability(F, ps.q/4)
    return F, ps.n*proba
def summarize(ps):
    F, f = p2_cyclotomic_error_probability(ps)
    print ("failure: %.1f = 2^%.1f"%(f, log(f + 2.**(-300))/log(2)))

if __name__ == "__main__":
    # Parameter sets
    ps_light = KyberParameterSet(256, 2, 3, 3, 3329, 2**12, 2**10, 2**4, ke_ct=2) #orig: 2^-139
    ps_recommended = KyberParameterSet(256, 3, 2, 2, 3329, 2**12, 2**10, 2**4) #orig: 2^-165
    ps_paranoid = KyberParameterSet(256, 4, 2, 2, 3329, 2**12, 2**11, 2**5) #orig: 2^-175

    # Analyses
    print ("Kyber512 (light):")
    summarize(ps_light)
    print ()

    print ("Kyber768 (recommended):")
    summarize(ps_recommended)
    print ()

    print ("Kyber1024 (paranoid):")
    summarize(ps_paranoid)
    print ()

    # Parameter sets
    ps_emlkem512 = KyberParameterSet(256, 2, 3, 3, 3329, 2**8, 2**8, 2**4, ke_ct=2) # 2^-139
    ps_emlkem768 = KyberParameterSet(256, 3, 2, 2, 3329, 2**8, 2**8, 2**4) # 2^-165
    ps_emlkem1024 = KyberParameterSet(256, 4, 2, 2, 3329, 2**9, 2**8, 2**3) # 2^-175

    # Analyses
    print ("eMLKEM-512:")
    summarize(ps_emlkem512)
    print ()

    print ("eMLKEM-768:")
    summarize(ps_emlkem768)
    print ()

    print ("eMLKEM-1024:")
    summarize(ps_emlkem1024)
    print ()