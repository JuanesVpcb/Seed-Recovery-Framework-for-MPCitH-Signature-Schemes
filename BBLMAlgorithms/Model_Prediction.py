# Librerías estándar de Python
import gc
import math
import os
import random
import time
import traceback
from collections import defaultdict
from functools import lru_cache
from itertools import product

# Librerías externas
from bitarray import bitarray

# Módulos del proyecto
from  BBLMAlgorithms.candidate import ChunkCandidate
from  BBLMAlgorithms.okeanode import initialize

# --- ML / utilidades ---
import numpy as np
try:
    import tensorflow as tf
except Exception:
    tf = None  # permite importar el módulo aunque no esté TF instalado


def decay_seed(s_star, alpha, beta):
    """
    Simula el decaimiento de la semilla original s* para obtener s_tilde.
    """
    s_tilde = bitarray()
    for bit in s_star:
        if bit == 0:
            flipped = 1 if random.random() < alpha else 0
        else:
            flipped = 0 if random.random() < beta else 1
        s_tilde.append(flipped)
    return s_tilde

def build_posteriors_from_tilde(s_tilde, alpha, beta):
    """
    Construye la matriz de posteriors P[j][b] = Pr(s*_j = b | s̃_j)
    """
    P = []
    for obs_bit in s_tilde:
        if obs_bit == 0:
            denom = (1 - alpha) + beta
            P.append([
                (1 - alpha) / denom,  # Pr(s*_j = 0 | s̃_j = 0)
                beta / denom          # Pr(s*_j = 1 | s̃_j = 0)
            ])
        else:  # obs_bit == 1
            denom = alpha + (1 - beta)
            P.append([
                alpha / denom,        # Pr(s*_j = 0 | s̃_j = 1)
                (1 - beta) / denom    # Pr(s*_j = 1 | s̃_j = 1)
            ])
    return P

def posterior_probability(observed_bit, candidate_bit, alpha, beta):
    """
    Calcula la probabilidad P(s* = candidate_bit | observed_bit) bajo el modelo CBPM para Cold Boot Attacks.
    
    Parámetros:
    - observed_bit: bit observado desde memoria (0 o 1), es decir, \tilde{s}_j
    - candidate_bit: valor que se quiere evaluar como el original s*_j (0 o 1)
    - alpha: probabilidad de flip de 0 a 1
    - beta: probabilidad de flip de 1 a 0

    Retorna:
    - Probabilidad condicional P(s*_j = candidate_bit | \tilde{s}_j)
    """

    if observed_bit == 0:
        if candidate_bit == 0:
            return (1 - alpha) / (1 - alpha + beta)
        else:  # candidate_bit == 1
            return beta / (1 - alpha + beta)
    elif observed_bit == 1:
        if candidate_bit == 0:
            return alpha / (alpha + (1 - beta))
        else:  # candidate_bit == 1
            return (1 - beta) / (alpha + (1 - beta))
    else:
        raise ValueError("observed_bit debe ser 0 o 1")


def score(candidate_bits, observed_bits, alpha, beta):
    """
    Calcula el log-likelihood score de una semilla candidata bajo el modelo CBPM.

    Parámetros:
    - candidate_bits: lista de bits candidatos, ej: [0, 1, 0, 1, ...]
    - observed_bits: lista de bits observados desde la memoria, misma longitud
    - alpha: probabilidad de flip de 0 a 1
    - beta: probabilidad de flip de 1 a 0

    Retorna:
    - Score (log-likelihood total)
    """

    if len(candidate_bits) != len(observed_bits):
        raise ValueError("candidate_bits y observed_bits deben tener la misma longitud")

    score = 0.0
    for cj, sj in zip(candidate_bits, observed_bits):
        prob = posterior_probability(observed_bit=sj, candidate_bit=cj, alpha=alpha, beta=beta)
        score += math.log(prob)

    return score

def extract_chunk(seed: bitarray, start: int, end: int) -> bitarray:
    return seed[start:end]

@lru_cache(maxsize=4096)
def safe_log(x):
    return math.log(x)

@lru_cache(maxsize=32)
def get_bit_combinations(w):
    """
    Devuelve todas las combinaciones posibles de bits de longitud w.
    Usa cache para evitar recomputarlas si ya se han calculado antes.
    """
    return list(product([0, 1], repeat=w))

def generate_candidates(P, W, w, eta, mu, scale=10000.0):
    """
    Algoritmo 1 (versión con xi explícito): genera bloques de candidatos usando OKEA.
    """
    if W % w != 0:
        raise ValueError("W debe ser divisible por w")
    N = W // w  # Número total de chunks

    if N % eta != 0:
        raise ValueError("Número de chunks no divisible por η")
    xi = N // eta  # Número de bloques

    chunk_lists = []

    # Paso 1: generar candidatos individuales por chunk
    for i in range(N):
        start = i * w
        end = start + w
        P_chunk = P[start:end]

        # ✅ Nueva línea: precalculamos logs por bit
        logs = [(safe_log(p0), safe_log(p1)) for (p0, p1) in P_chunk]

        candidates = []
        for bits in get_bit_combinations(w):
            score = -sum(logs[j][bit] for j, bit in enumerate(bits))
            ba = bitarray(bits)
            candidates.append(ChunkCandidate(score, ba))

        candidates.sort(key=lambda c: c.score)
        chunk_lists.append(candidates)

    # Paso 2: agrupar chunks por bloques usando xi
    blocks = []
    for i in range(xi):  # uso explícito de xi
        start = i * eta
        chunk_group = chunk_lists[start:start+eta]
        okea_tree = initialize(chunk_group, 0, eta - 1, scale=scale)

        block_candidates = []
        for j in range(mu):
            cand = okea_tree.getCandidate(j)
            if cand is None:
                break
            block_candidates.append(cand)

        blocks.append(block_candidates)

        # liberar estructuras internas del árbol OKEA
        del okea_tree

    return blocks

def generate_candidates_trimmed(P, W, w, eta, mu, scale=10000.0):
    """
    Genera bloques de candidatos usando OKEA.
    Cambio clave: limitar cada CHUNK a sus top-μ antes de construir el árbol,
    para evitar explosión combinatoria en initialize(...).
    """
    import sys, math

    if W % w != 0:
        raise ValueError("W debe ser divisible por w")
    N = W // w  # número total de chunks

    if N % eta != 0:
        raise ValueError("Número de chunks no divisible por η")
    xi = N // eta  # número de bloques

    chunk_lists = []

    # Paso 1: candidatos por chunk
    for i in range(N):
        start = i * w
        end = start + w
        P_chunk = P[start:end]

        # precálculo de logs por bit
        logs = [(safe_log(p0), safe_log(p1)) for (p0, p1) in P_chunk]

        candidates = []
        for bits in get_bit_combinations(w):  # 2^w combinaciones
            sc = -sum(logs[j][bit] for j, bit in enumerate(bits))
            ba = bitarray(bits)
            candidates.append(ChunkCandidate(sc, ba))

        candidates.sort(key=lambda c: c.score)

        # ★ recorte a top-μ (si μ > 2^w, el slicing no falla, pero mu = min(mu, 2^w))
        if mu is not None:
            candidates = candidates[:mu]

        chunk_lists.append(candidates)

    # Paso 2: agrupar chunks por bloques y construir OKEA con guardas
    blocks = []
    MAX_INDEX = sys.maxsize  # límite práctico para tamaños indexables (Py_ssize_t)

    for i in range(xi):
        start = i * eta
        chunk_group = chunk_lists[start:start + eta]

        # ✅ Guarda preventiva: comprobar tamaño combinatorio μ^eta
        # usamos log2 para evitar overflow en potencias
        sum_log2 = 0.0
        for lst in chunk_group:
            ln = max(1, len(lst))   # por seguridad
            sum_log2 += math.log2(ln)

        # si el tamaño estimado del producto supera el índice máximo, abortar temprano
        if sum_log2 >= math.log2(MAX_INDEX):
            print(f"❌ Error: combinación por bloque demasiado grande (μ^{eta} ≈ 2^{sum_log2:.2f} > {MAX_INDEX})")
            raise RuntimeError(
                f"Combinación por bloque demasiado grande: "
            )

        # construir OKEA
        okea_tree = initialize(chunk_group, 0, eta - 1, scale=scale)

        block_candidates = []
        for j in range(mu):
            cand = okea_tree.getCandidate(j)
            if cand is None:
                break
            block_candidates.append(cand)

        blocks.append(block_candidates)

        del okea_tree  # liberar estructuras internas

    return blocks

def create(L, B1, B2, W, w, eta, mu, scale=10000):
    """
    Construye la matriz B[i][b] como en el Algoritmo 2 del paper, pero usando
    defaultdict(int) internamente para eficiencia, y convirtiendo a list al final.

    Args:
        L: lista de bloques con candidatos
        B1, B2: límite inferior y superior de score permitido
        W, w, eta, mu: parámetros del sistema
        scale: factor para convertir scores a enteros

    Returns:
        Matriz B[i][b] como lista de listas de enteros
    """
    N = W // w
    xi = N // eta

    # Estructura interna con acceso eficiente
    B_sparse = [defaultdict(int) for _ in range(xi)]

    # Precalcular pesos enteros por bloque
    weights_by_block = [
        [cand.to_weight(scale) for cand in block]
        for block in L
    ]

    # --- Base: último bloque (i = xi - 1) ---
    i = xi - 1
    for b in range(B2):
        for r in weights_by_block[i]:
            if B1 - b <= r < B2 - b:
                B_sparse[i][b] += 1

    # --- Recursión: bloques anteriores ---
    for i in reversed(range(xi - 1)):
        for b in range(B2):
            total = 0
            for r in weights_by_block[i]:
                next_b = b + r
                if next_b in B_sparse[i + 1]:
                    total += B_sparse[i + 1][next_b]
            if total > 0:
                B_sparse[i][b] = total

    # --- Conversión a lista de listas ---
    B = [[0] * B2 for _ in range(xi)]
    for i in range(xi):
        for b, count in B_sparse[i].items():
            B[i][b] = count

    return B

# --- Versión rápida para prefijos [Bmin, Bk) en una sola pasada ---
from collections import defaultdict
from bisect import bisect_left

def create_multi_prefix_fast(L, Bmin, edges, W, w, eta, mu, scale=10000, weights_by_block=None):
    """
    Devuelve NE_pref[k] = # { combinaciones con suma S en [Bmin, edges[k+1)) }.
    Hace una sola DP dispersa (suffix-first) y usa dos podas:
      - Superior: descarta s >= Bmax (no entra a ningún prefijo)
      - Inferior: descarta s' si s' + max_left < Bmin (ni con todo lo que falta llega)
    Requisitos:
      - edges ordenado, edges[0] == Bmin, edges[-1] == Bmax.
      - weights_by_block opcional (para no recalcular to_weight).
    """
    N  = W // w
    xi = N // eta
    assert edges and edges[0] == Bmin, "edges[0] debe ser Bmin"
    Bmax = edges[-1]

    if weights_by_block is None:
        weights_by_block = [[cand.to_weight(scale) for cand in block] for block in L]

    # máximos por bloque (para podas inferiores)
    max_per_block = [max(block) for block in weights_by_block]

    # rem_max_left[j] = suma máxima de bloques [0..j] (izquierda de j)
    rem_max_left = [0] * xi
    acc = 0
    for j in range(xi):
        acc += max_per_block[j]
        rem_max_left[j] = acc

    # Base: último bloque (i = xi-1)
    # next_counts: sumas del "suffix" ya combinado → multiplicidades
    next_counts = defaultdict(int)
    # En i = xi-1 aún faltan bloques [0..xi-2] a la izquierda (pueden sumar)
    # Condición segura: r + rem_max_left[xi-2] >= Bmin  (si xi-2 >= 0)
    max_left_after_last = rem_max_left[xi-2] if xi-2 >= 0 else 0
    for r in weights_by_block[xi - 1]:
        if r >= Bmax:
            continue
        if r + max_left_after_last >= Bmin:
            next_counts[r] += 1

    # Combinar hacia i=0
    for i in range(xi - 2, -1, -1):
        curr = defaultdict(int)
        wi = weights_by_block[i]
        max_left = rem_max_left[i-1] if i-1 >= 0 else 0

        # Poda inferior previa: mantener solo s' viables (s' + max_left >= Bmin)
        for s_prime, cnt in next_counts.items():
            if s_prime + max_left < Bmin:
                continue
            # Extender con pesos del bloque i, podando contra Bmax
            t = s_prime
            for r in wi:
                s = t + r
                if s < Bmax:
                    curr[s] += cnt

        next_counts = curr

    # Barrido de prefijos (ordenar sumas y acumular)
    if not next_counts:
        return [0] * (len(edges) - 1)

    sums_items = sorted(next_counts.items())  # (S, count)
    sums, cnts = zip(*sums_items)

    start = bisect_left(sums, Bmin)
    res = []
    acc = 0
    idx = start
    for hi in edges[1:]:
        while idx < len(sums) and sums[idx] < hi:
            acc += cnts[idx]
            idx += 1
        res.append(acc)
    return res


def findOptimalB2(L, B1, Bmax, W, w, eta, mu, Btime, Bmemory, Cbase, Cblock, Coracle, scale=10000):
    """
    Búsqueda binaria de B2 con el modelo EXACTO del paper:

        M = μ·W + ξ·μ·log2(Bmax) + (W/(η·w))·B2·ceil(ξ·log2(μ))
          = μ·W + ξ·μ·log2(Bmax) + ξ·B2·ceil(ξ·log2(μ)),  con  ξ = W/(η·w)

    Tiempo:
        T = Ncands · (Cbase + μ·ξ·Cblock + Coracle)
    """
    # ξ = W/(η·w)
    N = W // w
    xi = N // eta

    # anchuras (exactas según paper)
    log2_Bmax = math.log2(Bmax)                      # ← sin ceil, ni clamps
    ceil_xi_log2_mu = math.ceil(xi * math.log2(mu))  # ← solo aquí hay ceil

    low, high = B1, Bmax
    best_B2 = None

    while low <= high:
        mid = (low + high) // 2

        # construir B y contar candidatos en [B1, mid)
        B = create(L, B1, mid, W, w, eta, mu, scale)
        Ncands = B[0][0]

        # tiempo y memoria (paper)
        T = Ncands * (Cbase + mu * xi * Cblock + Coracle)
        M = (mu * W) + (xi * mu * log2_Bmax) + (xi * mid * ceil_xi_log2_mu)

        if T <= Btime and M <= Bmemory:
            best_B2 = mid
            low = mid + 1
        else:
            high = mid - 1

    return best_B2

def getMinimumScore(L):
    """
    Retorna el score mínimo total posible combinando
    el peor candidato (menor score) de cada bloque.
    """
    return sum(block[0].score for block in L)

def getMaximumScore(L):
    """
    Retorna el score máximo total posible combinando
    el mejor candidato (mayor score) de cada bloque.
    """    
    return sum(block[-1].score for block in L)

def getMinimumWeight(L, scale=10000):
    return sum(block[0].to_weight(scale) for block in L)

def getMaximumWeight(L, scale=10000):
    return sum(block[-1].to_weight(scale) for block in L)

def _prev_pow2(x: int) -> int:
    if x < 1:
        return 1
    return 1 << (x.bit_length() - 1)  # para x=pot2 devuelve x

def _next_pow2(x: int) -> int:
    if x < 1:
        return 1
    return 1 << ((x - 1).bit_length())

def _nearest_pow2(x: int) -> int:
    if x < 1:
        return 1
    p = _prev_pow2(x)
    n = _next_pow2(x)
    return p if (x - p) <= (n - x) else n

def choose_m_pow2(W, w, eta, Bmin, Bmax, mode="nearest", m_min_pow=3, m_max_pow=5):
    """
    Elige m como potencia de 2 en [2^m_min_pow, 2^m_max_pow], donde
    m_base ≈ 2 * (W / (eta * w)). Devuelve (m, cuts) con cortes
    estrictamente crecientes que particionan [Bmin, Bmax) en m segmentos.

    mode: "nearest" | "ceil" | "floor"
    """
    # Validaciones básicas
    if w <= 0:
        raise ValueError("w debe ser > 0")
    if eta <= 0:
        raise ValueError("eta debe ser > 0")

    # Rango en enteros escalados
    rng = max(1, int(Bmax) - int(Bmin))  # al menos 1 unidad

    # m_base ≈ 2 * (W / (eta * w))
    # (usa floor conservador; si prefieres, cambia a round)
    xi = (W // w) // eta
    m_base = max(1, 2 * xi)

    m_min = 1 << int(m_min_pow)  # 2^m_min_pow (p.ej., 8)
    m_max = 1 << int(m_max_pow)  # 2^m_max_pow (p.ej., 32)

    # Elegir potencia de 2 según modo
    if mode == "ceil":
        m = _next_pow2(m_base)
    elif mode == "floor":
        m = _prev_pow2(m_base)
    else:  # "nearest"
        m = _nearest_pow2(m_base)

    # Acotar a [m_min, m_max]
    m = max(m_min, min(m_max, m))

    # Si m > rng, reduce m manteniendo potencia de 2 para evitar segmentos vacíos
    while m > rng and m > 1:
        m >>= 1  # divide entre 2, sigue siendo potencia de 2

    # Construir cortes estrictamente crecientes repartiendo el residuo
    # Queremos m segmentos enteros que sumen rng:
    # width_base = rng // m, rem = rng % m
    # Los primeros 'rem' segmentos tendrán (width_base + 1), el resto width_base.
    width_base, rem = divmod(rng, m)
    edges = [int(Bmin)]
    for i in range(m):
        step = width_base + (1 if i < rem else 0)
        edges.append(edges[-1] + step)
    # edges[0]=Bmin, edges[-1]=Bmin+rng=Bmax

    # Cortes = bordes superiores de cada segmento
    cuts = edges[1:]  # len = m, estrictamente crecientes

    return m, cuts

def score_from_candidate_lists(s_star, L, W, w, eta, scale=10000):
    N = W // w
    xi = N // eta
    score_total = 0
    idx = 0
    for i in range(xi):
        chunk_bits = bitarray()
        for _ in range(eta):
            chunk_bits.extend(s_star[idx:idx + w])
            idx += w
        for cand in L[i]:
            if cand.bits == chunk_bits:
                score_total += cand.to_weight(scale)   # << usar mismo scale
                break
        else:
            return None
    return score_total

# --- Monte Carlo estratificado por sub-bandas de score -----------------------

def montecarlo_score_only_prefix(
    config, noise, N=10, verbose=False, seed=42,
    scale=10000, error_log_dir="errores",
    m_mode="nearest", m_min_pow=3, m_max_pow=5,
    last_prefix_inclusive=True,         # último prefijo [Bmin, Bmax] inclusivo en el borde derecho
    log_per_run_errors=True             # guarda traceback por iteración con excepción
):
    """
    Monte Carlo con estratificación por PREFIJOS: [Bmin, edges[k+1))
    - Una sola DP por iteración via create_multi_prefix_fast (prefijos directos).
    - Bandas disjuntas (si se desean) se derivan por diferencias de prefijos.
    - Mismos acumuladores/promedios que la versión previa.
    """

    W, mu, w, eta = config
    alpha, beta = noise

    excluded_seeds = 0          # semilla real excluida por top-μ
    exception_failures = 0      # iteraciones con excepción
    valid_failures = 0          # score_real fuera de [Bmin, Bmax) (semiabierto) o no cayó en ningún prefijo
    errors = 0
    total_time = 0.0

    SBmin_sum = 0
    SBmax_sum = 0

    # Acumuladores (dimensionados al primer 'm' válido)
    SNE_bin_sum  = None   # sumatoria de NE por banda disjunta
    SC_bin_sum   = None   # sumatoria de 1{score_real en banda k}
    SNE_pref_sum = None   # sumatoria de NE en prefijos [Bmin, edges[k+1))
    SC_pref_sum  = None   # sumatoria de 1{score_real en prefijo k}

    last_edges = None
    last_m = None

    os.makedirs(error_log_dir, exist_ok=True)

    try:
        for it in range(N):
            try:
                random.seed(seed + it)

                # 1) Muestra semilla y canal
                s_star  = bitarray([random.getrandbits(1) for _ in range(W)])
                s_tilde = decay_seed(s_star, alpha, beta)
                P       = build_posteriors_from_tilde(s_tilde, alpha, beta)

                t0 = time.time()

                # 2) Genera candidatos por bloque (top-μ por bloque)
                L = generate_candidates_trimmed(P, W, w, eta, mu, scale)

                # 3) Score real (None => excluida por top-μ en algún bloque)
                score_real = score_from_candidate_lists(s_star, L, W, w, eta, scale=scale)
                if score_real is None:
                    excluded_seeds += 1
                    if verbose:
                        print(f"[{it+1:02d}/{N}] ❌ semilla real excluida (top-μ)")
                    # limpieza
                    try:
                        del L, P, s_star, s_tilde
                    except:
                        pass
                    gc.collect()
                    continue

                # 4) Rango de scores (enteros escalados, consistente con to_weight/scale)
                Bmin = getMinimumWeight(L, scale)
                Bmax = getMaximumWeight(L, scale)

                SBmin_sum += Bmin
                SBmax_sum += Bmax

                # 5) Elegir m y cortes (prefijos)
                m, cuts = choose_m_pow2(
                    W, w, eta, Bmin, Bmax,
                    mode=m_mode, m_min_pow=m_min_pow, m_max_pow=m_max_pow
                )
                edges = [Bmin] + list(cuts)   # edges[0]==Bmin, edges[-1]==Bmax
                last_edges = edges
                last_m = m

                if verbose:
                    print(f"[{it+1:02d}/{N}] m={m}, cortes={cuts}, Bmin={Bmin}, Bmax={Bmax}, score_real={score_real}")

                # Inicializar acumuladores en la primera corrida válida
                if SNE_bin_sum is None:
                    SNE_bin_sum  = [0] * m
                    SC_bin_sum   = [0] * m
                    SNE_pref_sum = [0] * m
                    SC_pref_sum  = [0] * m

                # 6) PREFIJOS directos con UNA sola DP (rápido)
                weights_by_block = [[cand.to_weight(scale) for cand in block] for block in L]

                NE_pref = create_multi_prefix_fast(
                    L, Bmin, edges, W, w, eta, mu, scale,
                    weights_by_block=weights_by_block
                )  # len = m, NE_pref[k] = #{S : Bmin ≤ S < edges[k+1]}

                # 7) Localizar score_real en prefijos y derivar "bandas" si se necesitan
                C_pref = [0] * m
                idx_real = None
                if Bmin <= score_real < Bmax:
                    # primer prefijo cuyo borde superior supera score_real
                    # (score_real ∈ [Bmin, edges[k+1]))
                    for k in range(m):
                        if score_real < edges[k+1]:
                            idx_real = k
                            for j in range(k, m):
                                C_pref[j] = 1  # desde k hacia adelante, todos los prefijos lo contienen
                            break
                elif last_prefix_inclusive and score_real == Bmax:
                    # caso borde: último prefijo inclusivo en el borde derecho
                    C_pref[-1] = 1
                    idx_real = m - 1

                if idx_real is None and not (last_prefix_inclusive and score_real == Bmax):
                    # no cayó en ningún prefijo (intervalos semiabiertos)
                    valid_failures += 1

                # Bandas disjuntas derivadas de prefijos (útil para comparabilidad con versiones previas)
                NE_bin = [NE_pref[0]] + [NE_pref[i] - NE_pref[i-1] for i in range(1, m)]
                C_bin  = [C_pref[0]]  + [1 if C_pref[i] and not C_pref[i-1] else 0 for i in range(1, m)]

                # 8) Acumular para promediar
                for k in range(m):
                    SNE_bin_sum[k]  += NE_bin[k]
                    SC_bin_sum[k]   += C_bin[k]
                    SNE_pref_sum[k] += NE_pref[k]
                    SC_pref_sum[k]  += C_pref[k]

                elapsed = time.time() - t0
                total_time += elapsed

                # limpieza explícita de objetos pesados de esta iteración
                try:
                    del NE_bin, C_bin, NE_pref, C_pref
                except:
                    pass
                try:
                    del edges, cuts
                except:
                    pass
                try:
                    del L, P, s_star, s_tilde, weights_by_block
                except:
                    pass
                gc.collect()

            except Exception:
                exception_failures += 1
                errors = exception_failures
                if log_per_run_errors:
                    fname = f"iter_error_W{W}_mu{mu}_w{w}_eta{eta}_a{int(alpha*1000)}_b{int(beta*100)}_it{it+1:03d}.txt"
                    with open(os.path.join(error_log_dir, fname), "w") as f:
                        f.write(traceback.format_exc())
                if verbose:
                    print(f"[{it+1:02d}/{N}] ⚠️ excepción en la iteración; registrada y continuando.")
                # limpieza robusta también en error
                for _name in ("NE_bin","C_bin","NE_pref","C_pref","edges","cuts","L","P","s_star","s_tilde","weights_by_block"):
                    try:
                        del locals()[_name]
                    except:
                        pass
                gc.collect()
                continue

            # purga periódica de caches para controlar RAM
            if (it + 1) % 10 == 0:
                get_bit_combinations.cache_clear()
                safe_log.cache_clear()


        if exception_failures > 0:
            return None

        # 9) Agregados finales
        N_valid = max(0, N - excluded_seeds - exception_failures)
        denom = max(1, N_valid)

        result = {
            "W": W, "mu": mu, "w": w, "eta": eta,
            "alpha": alpha, "beta": beta,
            "N": N,
            "N_valid": N_valid,
            "excluded_seeds": excluded_seeds,
            "exception_failures": exception_failures,
            "valid_failures": valid_failures,
            "errors": errors,  # alias
            "avg_time_sec": round(total_time / denom, 4),
            "Bmin_avg": SBmin_sum // denom if denom > 0 else 0,
            "Bmax_avg": SBmax_sum // denom if denom > 0 else 0,
            "m_bins": (last_m or 0),
            "edges_last": last_edges or [],
            # Promedios por banda disjunta (derivadas)
            "NE_bin_avg":  [x / denom for x in (SNE_bin_sum  or [])],
            "C_bin_rate":  [round(x / denom, 4) for x in (SC_bin_sum   or [])],
            # Promedios por prefijo [Bmin, edges[k+1))
            "NE_pref_avg": [x / denom for x in (SNE_pref_sum or [])],
            "C_pref_rate": [round(x / denom, 4) for x in (SC_pref_sum  or [])],
            # Tasas agregadas
            "excluded_rate": round(excluded_seeds / N, 4) if N > 0 else 0.0,
            "exception_rate": round(exception_failures / N, 4) if N > 0 else 0.0,
            "valid_failure_rate": round(valid_failures / max(1, N - excluded_seeds), 4) if N > 0 else 0.0,
            "seed": seed,
        }
        return result

    except Exception:
        fname = f"fatal_error_W{W}_mu{mu}_w{w}_eta{eta}_a{int(alpha*1000)}_b{int(beta*100)}.txt"
        with open(os.path.join(error_log_dir, fname), "w") as f:
            f.write(traceback.format_exc())
        if verbose:
            print(f"⚠️ Error crítico guardado en {fname}")
        return None


def is_valid_config(W, w, eta):
    return (w * eta) != 0 and W % (w * eta) == 0

def generar_parametros_validos(W_vals):
    """
    Genera todas las tuplas (W, μ, w, η) válidas según las restricciones:
    - W divisible por w
    - W divisible por η * w
    - μ es potencia de 2 hasta min(2^14, η * w)
    """
    configuraciones = []

    for W in W_vals:
        max_log_w = 4 #min(5, int.bit_length(W))  # evita w demasiado grandes
        w_vals = [2 ** i for i in range(2, max_log_w + 1)]  # ej: [4, 8, 16]

        for w in w_vals:
            if W % w != 0:
                continue

            # η debe cumplir que η * w divide a W
            eta_vals = sorted({
                2 ** k for k in range(1, int.bit_length(W // w) + 1)
                if ((2 ** k) * w) != 0 and W % ((2 ** k) * w) == 0
            })

            for eta in eta_vals:
                # μ: potencias de 2 hasta 2^14 o hasta η·w
                mu_vals = sorted({
                    2 ** k for k in range(1, min(6, eta * w) + 1)
                })

                for mu in mu_vals:
                    configuraciones.append((W, mu, w, eta))

    return configuraciones

def seedRecovery_ML_until24(
    P_post,                 # posteriors P[j][b] = Pr(s*_j=b | s̃_j); p.ej. build_posteriors_from_tilde
    G,                      # iterable de configs (W, mu, w, eta)
    model,                  # modelo Keras entrenado: inputs [W,w,mu,eta,alpha,beta,Bmin,B2]
    alpha, beta,            # parámetros del canal (features del modelo)
    *,
    # Presupuestos
    Btime=2**30, Bmemory=2**30, Cbase=2**5, Cblock=2**4, Coracle=2**6,
    scale=10_000,
    verbose=False
):
    """
    Algoritmo 7 hasta línea 24, *siempre* budget-aware:
      L7  : generar candidatos por bloque (OKEA) con trimming
      L8-9: calcular Bmin, Bmax (misma escala que to_weight/scale)
      L10 : obtener B2* vía findOptimalB2 con presupuesto
      L12 : (opcional) construir BM en [Bmin, B2*) para validar
      L13 : predecir P̂_success con el modelo ML
      L14-18: seleccionar la mejor configuración
      L21-24: retornar tupla y args para línea 25 (semilla/oráculo)
    Retorna:
      dict con keys:
        - best_score: P̂_success máximo
        - best: (W, μ, Bmin, B2*, w, η)
        - bestL: lista de bloques de candidatos de la mejor config
        - bestB2: entero B2*
        - args_seedSearch: args listos para la línea 25 (seedSearch)
    """
    if model is None:
        raise RuntimeError("Modelo Keras no cargado (model=None).")

    best_score = -1.0
    best = None
    bestL = None
    bestB2 = None

    for (W, mu, w, eta) in G:
        # Filtros de divisibilidad (líneas 4–5)
        if (W % w != 0) or (W % (eta * w) != 0):
            if verbose:
                print(f"skip: W={W}, w={w}, eta={eta} no divide W")
            continue

        # L7: candidatos por bloque con trimming
        L = generate_candidates_trimmed(P_post, W, w, eta, mu, scale)

        # L8–9: rango [Bmin, Bmax) en la misma escala
        Bmin = int(getMinimumWeight(L, scale))
        Bmax = int(getMaximumWeight(L, scale))
        if Bmax <= Bmin:
            if verbose:
                print(f"[W={W},w={w},η={eta},μ={mu}] Rango inválido: Bmin={Bmin}, Bmax={Bmax}")
            # liberación básica
            try:
                del L
            except:
                pass
            gc.collect()
            continue

        # L10: elegir B2* con presupuesto
        B2_star = findOptimalB2(
            L, Bmin, Bmax, W, w, eta, mu,
            Btime, Bmemory, Cbase, Cblock, Coracle, scale
        )
        if (B2_star is None) or (B2_star <= Bmin) or (B2_star > Bmax):
            if verbose:
                print(f"[W={W},w={w},η={eta},μ={mu}] B2* inválido: {B2_star}")
            try:
                del L
            except:
                pass
            gc.collect()
            continue

        # L12: (opcional de compatibilidad) construir BM en [Bmin, B2*)
        try:
            _ = create(L, Bmin, B2_star, W, w, eta, mu, scale)
        except Exception:
            pass

        # L13: predicción ML de P_success
        x = np.array([[float(W), float(w), float(mu), float(eta),
                       float(alpha), float(beta), float(Bmin), float(B2_star)]],
                     dtype="float32")
        P_hat = float(model.predict(x, verbose=0).ravel()[0])

        if verbose:
            print(f"P̂={P_hat:.4f}  (W={W}, w={w}, μ={mu}, η={eta}, Bmin={Bmin}, B2*={B2_star})")

        # L14–18: actualizar mejor
        if P_hat > best_score:
            best_score = P_hat
            best       = (W, mu, Bmin, B2_star, w, eta)
            bestL      = L
            bestB2     = B2_star
        else:
            # si no es mejor, libera L de esta config
            try:
                del L
            except:
                pass
            gc.collect()

    # L21–24: retorno
    if best is None:
        if verbose:
            print("No se encontró configuración válida bajo el presupuesto (⊥).")
        return None

    W_, mu_, Bmin_, B2_, w_, eta_ = best
    return {
        "best_score": best_score,
        "best":       best,         # (W, μ, Bmin, B2*, w, η)
        "bestL":      bestL,
        "bestB2":     bestB2,
        "args_seedSearch": {        # listo para la línea 25
            "L":   bestL,
            "Bmin": Bmin_,
            "B2":   B2_,
            "W":    W_,
            "w":    w_,
            "eta":  eta_,
            "mu":   mu_,
        }
    }

# ====== Grid ML estilo MonteCarlo con listas de presupuestos ======
import os, json, time, gc, random
from datetime import datetime
import numpy as np
import pandas as pd

try:
    import tensorflow as tf
except Exception:
    tf = None

print("\n🔍 Ejecutando grid ML (Algoritmo 7 hasta línea 24) con listas de B's ...\n")

# --- Listas de parámetros (igual formato que en MonteCarlo) ---
W_vals     = [128]                          # longitud total de la semilla
alpha_list = [0.001]                                  # probabilidad flip 0→1
beta_list  = [0.03, 0.05, 0.10, 0.15, 0.20, 0.25]     # probabilidad flip 1→0

# --- Listas de presupuestos (nuevas) ---
Btime_list   = [2**50]       # límites de tiempo (puedes añadir más)
Bmemory_list = [2**50]       # límites de memoria
Cbase_list   = [2**5]         # costo base
Cblock_list  = [2**4]         # costo por bloque
Coracle_list = [2**6]         # costo de oráculo

overwrite     = False
scale         = 10_000

# --- Rutas de salida ---
model_path     = "ML/modelo_prefijo_FINAL.keras"
resultados_dir = "resultados_ml_v2"
errores_dir    = "errores_ml_v2"
os.makedirs(resultados_dir, exist_ok=True)
os.makedirs(errores_dir, exist_ok=True)

if tf is None:
    raise RuntimeError("TensorFlow/Keras no disponible. Instala TF para usar esta versión ML.")

# Cargar el modelo solo una vez
model = tf.keras.models.load_model(model_path)

# Grid de configuraciones válidas (W, μ, w, η)
grid = list(generar_parametros_validos(W_vals))

def _gid(W, mu, w, eta, alpha, beta, Btime, Bmemory, Cbase, Cblock, Coracle):
    return (f"W{W}_mu{mu}_w{w}_eta{eta}_a{int(alpha*1000)}_b{int(beta*100)}"
            f"_Bt{int(np.log2(Btime))}_Bm{int(np.log2(Bmemory))}"
            f"_Cb{int(np.log2(Cbase))}_Cbl{int(np.log2(Cblock))}_Co{int(np.log2(Coracle))}")

rows = []
t0 = time.time()
k = 0
total = (len(grid) * len(alpha_list) * len(beta_list) *
         len(Btime_list) * len(Bmemory_list) * len(Cbase_list) *
         len(Cblock_list) * len(Coracle_list))

for (W, mu, w, eta) in grid:
    if (w * eta) == 0 or (W % (w * eta) != 0):
        continue

    for alpha in alpha_list:
        for beta in beta_list:
            for Btime in Btime_list:
                for Bmemory in Bmemory_list:
                    for Cbase in Cbase_list:
                        for Cblock in Cblock_list:
                            for Coracle in Coracle_list:
                                k += 1
                                gid = _gid(W, mu, w, eta, alpha, beta, Btime, Bmemory, Cbase, Cblock, Coracle)
                                filename_json = f"{gid}.json"
                                path_json = os.path.join(resultados_dir, filename_json)

                                if os.path.exists(path_json) and not overwrite:
                                    print(f"→ {gid} ... 🟡 existe, omitido")
                                    rows.append({
                                        "group_id": gid,
                                        "status": "SKIPPED",
                                        "best_score": float("nan"),
                                        "W": W, "mu": mu, "w": w, "eta": eta,
                                        "alpha": alpha, "beta": beta,
                                        "Btime": Btime, "Bmemory": Bmemory,
                                        "Cbase": Cbase, "Cblock": Cblock, "Coracle": Coracle,
                                        "Bmin": None, "B2": None,
                                        "path": path_json
                                    })
                                    continue

                                print(f"[{k}/{total}] → {gid} ... ejecutando (ML)")

                                # 1) Semilla y canal (como MonteCarlo)
                                try:
                                    from bitarray import bitarray
                                    random.seed(42)
                                    s_star  = bitarray([random.getrandbits(1) for _ in range(W)])
                                    s_tilde = decay_seed(s_star, alpha, beta)
                                    P_post  = build_posteriors_from_tilde(s_tilde, alpha, beta)
                                except Exception as e:
                                    with open(os.path.join(errores_dir, f"prep_error_{gid}.txt"), "w") as f:
                                        f.write(str(e))
                                    data = {
                                        "status": "EMPTY",
                                        "group_id": gid,
                                        "W": W, "mu": mu, "w": w, "eta": eta,
                                        "alpha": alpha, "beta": beta,
                                        "Btime": Btime, "Bmemory": Bmemory,
                                        "Cbase": Cbase, "Cblock": Cblock, "Coracle": Coracle,
                                        "timestamp": time.time()
                                    }
                                    with open(path_json, "w") as f:
                                        json.dump(data, f, indent=2)
                                    rows.append(data)
                                    continue

                                # 2) Ejecutar Algoritmo 7 hasta línea 24 (budget-aware + ML)
                                try:
                                    out = seedRecovery_ML_until24(
                                        P_post=P_post,
                                        G=[(W, mu, w, eta)],
                                        model=model,
                                        alpha=alpha, beta=beta,
                                        Btime=Btime, Bmemory=Bmemory,
                                        Cbase=Cbase, Cblock=Cblock, Coracle=Coracle,
                                        scale=scale,
                                        verbose=False
                                    )
                                except Exception as e:
                                    # Imprimir mensaje de error con traceback

                                    with open(os.path.join(errores_dir, f"exec_error_{gid}.txt"), "w") as f:
                                        f.write(str(e))
                                    out = None

                                # 3) Serializar resultado
                                if out is None:
                                    data = {
                                        "status": "EMPTY",
                                        "group_id": gid,
                                        "W": W, "mu": mu, "w": w, "eta": eta,
                                        "alpha": alpha, "beta": beta,
                                        "Btime": Btime, "Bmemory": Bmemory,
                                        "Cbase": Cbase, "Cblock": Cblock, "Coracle": Coracle,
                                        "timestamp": time.time()
                                    }
                                else:
                                    data = {
                                        "status": "OK",
                                        "group_id": gid,
                                        "best_score": float(out.get("best_score", float("nan"))),
                                        "best": out.get("best", None),
                                        "Bmin": int(out["args_seedSearch"]["Bmin"]),
                                        "B2": int(out["args_seedSearch"]["B2"]),
                                        "W": W, "mu": mu, "w": w, "eta": eta,
                                        "alpha": alpha, "beta": beta,
                                        "Btime": Btime, "Bmemory": Bmemory,
                                        "Cbase": Cbase, "Cblock": Cblock, "Coracle": Coracle,
                                        "timestamp": time.time()
                                    }

                                with open(path_json, "w") as f:
                                    json.dump(data, f, indent=2)

#                                rows.append(data)

                                # 4) Liberar memoria por combinación
                                try:
                                    del s_star, s_tilde, P_post, out, data
                                except Exception:
                                    pass
                                gc.collect()

# --- Guardar resumen global ---
summary_path = os.path.join(resultados_dir, "summary.csv")
df = pd.DataFrame(rows)
df.to_csv(summary_path, index=False)
dt = time.time() - t0
print(f"\n✅ Grid ML completado ({len(rows)} casos en {dt:.2f}s)")
print(f"Resumen: {summary_path}")

# --- Limpieza final ---
try:
    if hasattr(tf.keras.backend, "clear_session"):
        tf.keras.backend.clear_session()
except Exception:
    pass
gc.collect()
