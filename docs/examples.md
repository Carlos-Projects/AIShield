# Examples

## Basic Scan

```bash
aishield scan ./model/
```

## Dataset Analysis with Custom Threshold

```bash
aishield dataset ./training-data/ --outlier-threshold 2.0
```

## Pipeline Audit with Compliance

```bash
aishield pipeline ./project/ --compliance nist
```

## Weight Manifest

```bash
aishield manifest ./model/
aishield manifest ./model/ --verify
```

## JSON Output

```bash
aishield scan ./model/ --json | jq '.summary'
```

## HTML Report with Custom File Size

```bash
aishield scan ./large-model/ --html report.html --max-file-size 268435456
```
