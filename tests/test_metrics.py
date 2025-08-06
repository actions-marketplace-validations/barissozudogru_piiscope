import pandas as pd

from gdpr_privacy_app.api.detection.metrics import compute_k_anonymity, compute_l_diversity, compute_t_closeness


def test_k_anonymity():
    df = pd.DataFrame({
        'age': [25, 25, 30, 30, 30],
        'zip': ['12345', '12345', '12345', '67890', '67890'],
        'disease': ['flu', 'flu', 'flu', 'cold', 'cold'],
    })
    k = compute_k_anonymity(df, ['age', 'zip'])
    assert k == 1


def test_l_diversity():
    df = pd.DataFrame({
        'age': [25, 25, 30, 30, 30],
        'zip': ['12345', '12345', '12345', '67890', '67890'],
        'disease': ['flu', 'flu', 'flu', 'cold', 'cancer'],
    })
    l = compute_l_diversity(df, ['age', 'zip'], 'disease')
    # Expect min number of distinct diseases per quasi group is 1 (for 30,67890)
    assert l == 1


def test_t_closeness():
    df = pd.DataFrame({
        'age': [25, 25, 30, 30, 30],
        'zip': ['12345', '12345', '12345', '67890', '67890'],
        'disease': ['flu', 'flu', 'flu', 'cold', 'cold'],
    })
    t = compute_t_closeness(df, ['age', 'zip'], 'disease')
    assert 0 <= t <= 1