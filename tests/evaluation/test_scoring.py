import unittest

from run import score, spans


def label(kind, start, end):
    return {'entity_type': kind, 'start': start, 'end': end}


class ScoringTests(unittest.TestCase):
    def test_exact_type_and_span_required_and_duplicates_count_as_false_positives(self):
        corpus = {'cases': [{'id': 'a', 'category': 'text', 'text': 'abc def ghi',
                            'expected': [label('Email', 0, 3), label('Ssn', 4, 7)]}]}
        predicted = [{'id': 'a', 'findings': [label('Email', 0, 3), label('Email', 0, 3),
                                           label('PhoneNumber', 4, 7), label('Ssn', 4, 6)]}]
        result = score(corpus, predicted)['overall']
        self.assertEqual(result, dict(tp=1, fp=3, fn=1, precision=0.25, recall=0.5, f1=1/3))

    def test_utf8_boundaries(self):
        self.assertEqual(sum(spans([label('Email', 3, 6)], 'é abc').values()), 1)
        for start, end in [(1, 2), (0, 9), (3, 3), (-1, 2)]:
            with self.assertRaises(ValueError):
                spans([label('Email', start, end)], 'é abc')

    def test_nested_findings_count_independently(self):
        items = [label('Url', 0, 12), label('Email', 4, 8)]
        corpus = {'cases': [{'id': 'a', 'category': 'url', 'text': 'abcdefghijkl', 'expected': items}]}
        self.assertEqual(score(corpus, [{'id': 'a', 'findings': items}])['overall']['tp'], 2)

    def test_negative_cases_and_undefined_metrics(self):
        corpus = {'cases': [{'id': 'a', 'category': 'clean', 'text': 'abc', 'expected': []}]}
        clean = score(corpus, [{'id': 'a', 'findings': []}])
        self.assertIsNone(clean['overall']['precision'])
        self.assertIsNone(clean['overall']['recall'])
        self.assertEqual(clean['negative_case_false_positive_rate'], 0)
        flagged = score(corpus, [{'id': 'a', 'findings': [label('Email', 0, 3)]}])
        self.assertEqual(flagged['negative_case_false_positive_rate'], 1)

    def test_missing_duplicate_or_unknown_case_is_rejected(self):
        corpus = {'cases': [{'id': 'a', 'category': 'clean', 'text': 'abc', 'expected': []}]}
        for predictions in [[], [{'id': 'b', 'findings': []}],
                            [{'id': 'a', 'findings': []}] * 2]:
            with self.assertRaises(ValueError):
                score(corpus, predictions)


if __name__ == '__main__':
    unittest.main()
