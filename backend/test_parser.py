from parsers import parse_csv_statement

sample_csv = b"""data,descrição,valor,categoria
23/03/2026,Pizza Hut,-85.00,Alimentação
22/03/2026,Transferência Recebida,1000.00,Transferência
"""

def test_parser():
    transactions = parse_csv_statement(sample_csv)
    assert len(transactions) == 2
    assert transactions[0]['description'] == 'Pizza Hut'
    assert transactions[0]['amount'] == 85.0
    assert transactions[0]['type'] == 'expense'
    assert transactions[1]['type'] == 'income'
    print("Parser test passed!")

if __name__ == '__main__':
    test_parser()
