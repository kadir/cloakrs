#!/usr/bin/env python3
"""Score exact typed UTF-8 byte spans; snapshot predictions for explicit review."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def spans(findings, text):
    boundaries = {0}
    offset = 0
    for char in text:
        offset += len(char.encode('utf-8'))
        boundaries.add(offset)
    result = []
    for item in findings:
        kind, start, end = item['entity_type'], item['start'], item['end']
        if not isinstance(kind, str) or not kind:
            raise ValueError('entity_type must be a nonempty string')
        if type(start) is not int or type(end) is not int or not (
                start in boundaries and end in boundaries and start < end):
            raise ValueError('spans must be nonempty UTF-8 byte ranges within the input')
        result.append((kind, start, end))
    return Counter(result)


def counts(tp=0, fp=0, fn=0):
    return {'tp': tp, 'fp': fp, 'fn': fn}


def metrics(value):
    tp, fp, fn = value['tp'], value['fp'], value['fn']
    return dict(value, precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None,
                f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None)


def score(corpus, predictions):
    ids = [case['id'] for case in corpus['cases']]
    observed_ids = [case['id'] for case in predictions]
    if len(set(ids)) != len(ids) or not ids:
        raise ValueError('corpus IDs must be unique and nonempty')
    if len(set(observed_ids)) != len(observed_ids) or set(ids) != set(observed_ids):
        raise ValueError('predictions must contain exactly one entry for every corpus ID')
    observed = {case['id']: case['findings'] for case in predictions}
    total, by_entity, by_category, errors = counts(), {}, {}, []
    clean_cases, clean_flagged = 0, 0
    for case in corpus['cases']:
        expected = spans(case['expected'], case['text'])
        if any(n != 1 for n in expected.values()):
            raise ValueError('duplicate ground-truth label')
        actual = spans(observed[case['id']], case['text'])
        matched, extra, missing = expected & actual, actual - expected, expected - actual
        category = by_category.setdefault(case['category'], counts())
        for field, items in [('tp', matched), ('fp', extra), ('fn', missing)]:
            total[field] += sum(items.values())
            category[field] += sum(items.values())
            for (kind, _, _), n in items.items():
                by_entity.setdefault(kind, counts())[field] += n
        if not expected:
            clean_cases += 1
            clean_flagged += bool(actual)
        if extra or missing:
            errors.append({'id': case['id'], 'extra': sorted(extra.elements()),
                           'missing': sorted(missing.elements())})
    return {'cases': len(ids), 'overall': metrics(total),
            'by_entity': {k: metrics(v) for k, v in sorted(by_entity.items())},
            'by_category': {k: metrics(v) for k, v in sorted(by_category.items())},
            'negative_cases': clean_cases, 'negative_cases_flagged': clean_flagged,
            'negative_case_false_positive_rate': clean_flagged / clean_cases if clean_cases else None,
            'errors': errors}


def canonical_predictions(predictions):
    return sorted((dict(id=p['id'], findings=sorted(p['findings'], key=lambda x:
                   (x['entity_type'], x['start'], x['end']))) for p in predictions),
                  key=lambda p: p['id'])


def percentile(values, percent):
    return sorted(values)[max(0, math.ceil(len(values) * percent / 100) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True,
                        help='prebuilt evaluate example; build separately for valid RSS measurements')
    parser.add_argument('--corpus', type=Path, default=HERE / 'corpus.json')
    parser.add_argument('--baseline', type=Path, default=HERE / 'baseline.json')
    parser.add_argument('--report', type=Path, default=ROOT / 'target/evaluation-report.json')
    parser.add_argument('--update-baseline', action='store_true', help='write new predictions for review')
    args = parser.parse_args()
    raw = args.corpus.read_bytes()
    corpus = json.loads(raw)
    # Validate labels even when the adapter cannot produce output.
    score(corpus, [{'id': c['id'], 'findings': []} for c in corpus['cases']])
    child = subprocess.run([str(args.binary.resolve()), str(args.corpus.resolve())],
                           capture_output=True, text=True, check=True)
    # No other child processes have run in this Python process. On Unix this is
    # the adapter's peak RSS, including initialization, JSON, and repeated scans.
    peak_rss = None
    if sys.platform in ('darwin', 'linux'):
        import resource
        peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if sys.platform == 'linux':
            peak_rss *= 1024
    output = json.loads(child.stdout)
    report = score(corpus, output['predictions'])
    # Hash content, not checkout line endings or JSON indentation (Windows CI).
    canonical_corpus = json.dumps(corpus, ensure_ascii=False, sort_keys=True,
                                  separators=(',', ':')).encode('utf-8')
    snapshot = {'corpus_sha256': hashlib.sha256(canonical_corpus).hexdigest(),
                'predictions': canonical_predictions(output['predictions'])}
    report.update(corpus_sha256=snapshot['corpus_sha256'],
                  corpus_version=corpus['version'], min_confidence=corpus['min_confidence'],
                  measurement={'platform': platform.platform(), 'machine': platform.machine(),
                               'binary': str(args.binary.resolve()),
                               'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                               'first_pass_ms': output['first_pass_ms'],
                               'warm_scan_p50_us': percentile(output['warm_scan_us'], 50),
                               'warm_scan_p95_us': percentile(output['warm_scan_us'], 95),
                               'warm_scan_samples': len(output['warm_scan_us']),
                               'repetitions': output['repetitions'], 'peak_rss_bytes': peak_rss})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('cases', 'overall', 'negative_case_false_positive_rate')}, indent=2))
    print('Detailed report:', args.report)
    if args.update_baseline:
        args.baseline.write_text(json.dumps(snapshot, indent=2) + '\n', encoding='utf-8')
        print('Baseline updated. Review every changed finding before committing.')
    elif snapshot != json.loads(args.baseline.read_text(encoding='utf-8')):
        print('Detection baseline changed. Review the report and baseline diff.', file=sys.stderr)
        return 1
    else:
        print('Detection baseline matches.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
