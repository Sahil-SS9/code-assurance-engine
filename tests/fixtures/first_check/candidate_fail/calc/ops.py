"""Arithmetic helpers with ONE planted defect (mul adds): the evaluator-owned failing fixture."""


def add(a, b):
    return a + b


def sub(a, b):
    return a - b


def mul(a, b):
    return a + b  # planted defect: the oracle must catch this
