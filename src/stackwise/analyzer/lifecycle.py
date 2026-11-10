"""AWS lifecycle dates that rules compare against at analyze time.

The dates are copied from the AWS pages in SOURCES. Each rule sees which versions are
past their date on the day the analysis runs, so a scheduled deprecation starts being
flagged without a code change. New versions and changed dates still need a refresh:
update the tables and AS_OF from SOURCES (a test fails once AS_OF is 90 days old).
"""

from __future__ import annotations

from datetime import date

AS_OF = date(2026, 11, 10)

SOURCES = {
    "lambda_runtimes": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
    "eks_versions": "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
}

# Runtime id -> deprecation date (the date AWS stops applying security patches).
LAMBDA_RUNTIME_DEPRECATION: dict[str, date] = {
    # Deprecated
    "python3.10": date(2026, 10, 31),
    "provided.al2": date(2026, 7, 31),
    "nodejs20.x": date(2026, 4, 30),
    "ruby3.2": date(2026, 3, 31),
    "python3.9": date(2025, 12, 15),
    "nodejs18.x": date(2025, 9, 1),
    "dotnet6": date(2024, 12, 20),
    "python3.8": date(2024, 10, 14),
    "nodejs16.x": date(2024, 6, 12),
    "dotnet7": date(2024, 5, 14),
    "java8": date(2024, 1, 8),
    "go1.x": date(2024, 1, 8),
    "provided": date(2024, 1, 8),
    "ruby2.7": date(2023, 12, 7),
    "nodejs14.x": date(2023, 12, 4),
    "python3.7": date(2023, 12, 4),
    "dotnetcore3.1": date(2023, 4, 3),
    "nodejs12.x": date(2023, 3, 31),
    "python3.6": date(2022, 7, 18),
    "dotnet5.0": date(2022, 5, 10),
    "dotnetcore2.1": date(2022, 1, 5),
    "nodejs10.x": date(2021, 7, 30),
    "ruby2.5": date(2021, 7, 30),
    "python2.7": date(2021, 7, 15),
    "nodejs8.10": date(2020, 3, 6),
    "nodejs4.3": date(2020, 3, 5),
    "nodejs4.3-edge": date(2020, 3, 5),
    "nodejs6.10": date(2019, 8, 12),
    "dotnetcore1.0": date(2019, 6, 27),
    "dotnetcore2.0": date(2019, 5, 30),
    "nodejs": date(2016, 8, 30),
    # Scheduled
    "dotnet8": date(2026, 11, 10),
    "dotnet9": date(2026, 11, 10),
    "ruby3.3": date(2027, 3, 31),
    "nodejs22.x": date(2027, 4, 30),
    "python3.11": date(2027, 6, 30),
    "java17": date(2027, 6, 30),
    "java11": date(2027, 6, 30),
    "java8.al2": date(2027, 6, 30),
    "ruby3.4": date(2028, 3, 31),
    "nodejs24.x": date(2028, 4, 30),
    "python3.12": date(2028, 10, 31),
    "dotnet10": date(2028, 11, 14),
    "ruby4.0": date(2029, 3, 31),
    "python3.13": date(2029, 6, 30),
    "python3.14": date(2029, 6, 30),
    "java25": date(2029, 6, 30),
    "java21": date(2029, 6, 30),
    "java17.al2023": date(2029, 6, 30),
    "java11.al2023": date(2029, 6, 30),
    "java8.al2023": date(2029, 6, 30),
    "provided.al2023": date(2029, 6, 30),
}

# (major, minor) -> end of EKS standard support. Versions older than the oldest entry are
# past standard support; versions newer than the newest entry are supported.
EKS_END_OF_STANDARD_SUPPORT: dict[tuple[int, int], date] = {
    (1, 37): date(2027, 12, 1),
    (1, 36): date(2027, 8, 2),
    (1, 35): date(2027, 3, 27),
    (1, 34): date(2026, 12, 2),
    (1, 33): date(2026, 7, 29),
    (1, 32): date(2026, 3, 23),
    (1, 31): date(2025, 11, 26),
}


def lifecycle_context(today: date | None = None) -> dict:
    """The lifecycle facts rule conditions see as `lifecycle`, as plain data."""
    today = today or date.today()
    deprecated = sorted(
        runtime for runtime, day in LAMBDA_RUNTIME_DEPRECATION.items() if day <= today
    )
    supported = [v for v, day in EKS_END_OF_STANDARD_SUPPORT.items() if day > today]
    # Past every listed date: anything newer than the table is still supported.
    newest = max(EKS_END_OF_STANDARD_SUPPORT)
    eks_min = min(supported) if supported else (newest[0], newest[1] + 1)
    return {
        "deprecated_lambda_runtimes": deprecated,
        "eks_min_standard_version": list(eks_min),
    }
