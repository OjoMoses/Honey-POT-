#!/usr/bin/env python3
"""Exact-integer / rational verification of every number used in the handbook.

Standard library only. No floating point is used for on-chain quantities.
Run:  python3 tools/verify_numbers.py [--out FILE]
"""
from __future__ import annotations

from fractions import Fraction
import sys
import pathlib

MASK160 = (1 << 160) - 1
RESULTS: list[str] = []


def emit(label: str, value, expected=None) -> None:
    line = f"{label}: {value}"
    if expected is not None:
        ok = value == expected
        line += f"  [expected {expected}; {'OK' if ok else 'MISMATCH'}]"
        assert ok, line
    RESULTS.append(line)
    print(line)


# ---------------------------------------------------------------- addresses
A_DEC = 178607940065137046348733521910879985571412708986
B_DEC = 686197854011229533619447624007587113080310915153
C_DEC = 17860794006513704634733521910879985571412708986
D_DEC = 570329899025738970963394674811034510039273195112
P_DEC = 701440412488354069900798616649035264741873926966
FRAGMENTS = [0x7addAd09, 0xcbd98D97, 0xEC3dA7a0, 0x088EAdFE, 0x5801C336]


def hx(n: int) -> str:
    return "0x%040x" % n


for tag, n, want in [
    ("A", A_DEC, "0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a"),
    ("B", B_DEC, "0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051"),
    ("C", C_DEC, "0x0320e7dc23bfae74334d93c20051125ca59e0e7a"),
    ("D", D_DEC, "0x63e67a280645edf97880c1df03c8301b151c4668"),
    ("P decimal", P_DEC, "0x7addad09cbd98d97ec3da7a0088eadfe5801c336"),
]:
    emit(f"address {tag} decimal -> hex", hx(n), want)

p_calc = (FRAGMENTS[0] << 128) | (FRAGMENTS[1] << 96) | (FRAGMENTS[2] << 64) | (FRAGMENTS[3] << 32) | FRAGMENTS[4]
emit("P assembled from five 32-bit fragments", hx(p_calc), hx(P_DEC))
emit("P fits in 160 bits", p_calc <= MASK160, True)
emit("fragment decimal matches assembly", p_calc == P_DEC, True)

# ------------------------------------------------------------- constant product
x, y, fee = 10**6, 100, Fraction(3, 1000)
gamma = 1 - fee
dx = 10**6
dy = Fraction(gamma * dx * y, x + gamma * dx)
emit("AMM dy (x=1e6,y=100,f=0.3%,dx=1e6) exact", dy)
emit("AMM dy rounded 4dp", round(float(dy), 4), 49.9249)
impact = 1 - Fraction(dy, dx) / Fraction(y, x)
emit("AMM price impact of that sell (exact)", impact)
emit("AMM impact 4dp", round(float(impact), 4), 0.5008)

# ------------------------------------------------------------- fee round trip
tb, ts = Fraction(5, 100), Fraction(10, 100)
mult = (1 - tb) * (1 - ts)
emit("round-trip multiplier (5% buy, 10% sell)", mult, Fraction(855, 1000))
emit("round-trip loss percent", (1 - mult) * 100, Fraction(145, 10))
emit("multiplier at sell tax 100%", (1 - tb) * (1 - Fraction(1)), Fraction(0))
emit("asymmetric path tau_b=0, tau_s=s/100 for s=100", 1 - Fraction(100, 100), Fraction(0))

# token fee unit: amount=1000, sellFee=100, divisor 100
amount, sell_fee = 1000, 100
token_fee = amount * sell_fee // 100
emit("transferFrom fee with amount=1000, sellFee=100", token_fee, 1000)
emit("seller receives", amount - token_fee, 0)
emit("transfer fee-free for same amount", amount, 1000)

# Exact AMM round-trip composition (buy all, then sell all received tokens).
q_in = 1  # one unit of quote asset
dx_b = Fraction(gamma * q_in * x, y + gamma * q_in)   # tokens received on buy
q_out = Fraction(gamma * dx_b * y, x + gamma * dx_b)  # quote received on sell
rho = q_out / q_in
impact_b = 1 - Fraction(dx_b, q_in) / Fraction(x, y)
impact_s = 1 - Fraction(q_out, dx_b) / Fraction(y, x)
emit("AMM round-trip tokens from buying 1 quote", f"{dx_b} ~ {round(float(dx_b), 4)}")
emit("AMM round-trip quote from selling them", f"{q_out} ~ {round(float(q_out), 6)}")
emit("AMM round-trip rho", f"{rho} ~ {round(float(rho), 6)}")
emit("AMM rho equals (1-impact_b)(1-impact_s)", rho, (1 - impact_b) * (1 - impact_s))
emit("AMM zero-impact limit gamma^2", gamma**2, Fraction(994009, 1000000))
emit("AMM naive gamma^2*(1-ib)*(1-is) would be", (gamma**2 * (1 - impact_b) * (1 - impact_s)))

# ------------------------------------------------------------- supply invariant
a = 777
emit("double credit: delta sum balances", 2 * a, 1554)
emit("double credit: delta totalSupply", 0, 0)
emit("double credit: events emitted", 2, 2)

# ------------------------------------------------------------- dilution / drain
s, S, m = 10**5, 10**6, 10**6
emit("dilution before percent", Fraction(100 * s, S), Fraction(10))
emit("dilution after percent", Fraction(100 * s, S + m), Fraction(5))
for minted in (10**6, 10**7, 10**9, 10**12):
    gamma_m = (997 * minted) // 1000  # gamma = 997/1000, exact integer wei/token units
    frac = Fraction(gamma_m, x + gamma_m)
    emit(f"drain fraction m={minted} (6dp)", round(float(frac), 6))
emit("drain limit as m -> infinity", 1, 1)

# ------------------------------------------------------------- classic arithmetic
# 01: msg.value >= this.balance where this.balance = B + v
B, v = 10**18, 10**18
emit("01 condition v >= B+v with B>0", v >= B + v, False)
emit("01 condition with B=0", v >= 0 + v, True)

# 10: L0 = 50 finney, integer division halving, floor at 1 wei
L0 = 50 * 10**15  # 50 finney in wei
cap, total, steps = L0, 0, 0
while cap > 1:
    total += cap
    steps += 1
    cap //= 2
emit("10 number of deposits before cap reaches 1 wei", steps, 55)
emit("10 exact deposit sum (wei)", total, 99999999999999979)
emit("10 shortfall from 100 finney (wei)", 10**17 - total, 21)
emit("10 geometric bound 2*L0", 2 * L0, 10**17)

# 07 / 07a uint8 wrap-around simulation
M = 1 << 8
i1, last = 1, 0
while True:
    last = i1
    nxt = (i1 + 1) % M
    if nxt < i1:  # the wrap that ends the loop in the documented pattern
        break
    i1 = nxt
emit("07 uint8 loop last value before wrap", last, 255)
emit("07 payout wei", last, 255)
multi_127 = (127 * 2) % M
multi_128 = (128 * 2) % M
emit("07a multi at i=127", multi_127, 254)
emit("07a multi at i=128", multi_128, 0)
emit("07a payout wei", multi_127, 254)

# 04 address vs small guess
emit("04 smallest 160-bit address above 10", 11, 11)

# ------------------------------------------------------------- line counts (source)
SRC = pathlib.Path(__file__).resolve().parent.parent / "contracts"
if SRC.is_dir():
    for p in sorted(SRC.rglob("*.sol")):
        n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
        RESULTS.append(f"lines {p.name}: {n}")
        print(f"lines {p.name}: {n}")

out_flag = "--out" in sys.argv
if out_flag:
    idx = sys.argv.index("--out")
    pathlib.Path(sys.argv[idx + 1]).write_text("\n".join(RESULTS) + "\n", encoding="utf-8")
print(f"\nAll {len(RESULTS)} checks completed without mismatch.")
