def risk_score(

ml_score,
keyword,
freq,
ip,
query_complexity

):

    score=(

    0.45*ml_score +

    0.20*keyword +

    0.15*freq +

    0.10*ip +

    0.10*query_complexity

    )

    return score