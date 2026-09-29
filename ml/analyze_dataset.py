from pathlib import Path

import pandas as pd


MANIFEST_PATH = Path("data/capture_manifest.csv")


def print_matrix(
    df,
    rows,
    columns,
    title,
):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    matrix = pd.crosstab(
        df[rows],
        df[columns],
    )

    print(matrix.to_string())


def main():

    df = pd.read_csv(
        MANIFEST_PATH
    )

    print(
        f"Total sessions: {len(df)}"
    )

    print_matrix(
        df,
        "traffic_class",
        "mode",
        "TRAFFIC CLASS × VPN MODE",
    )

    print_matrix(
        df,
        "traffic_class",
        "cipher_suite",
        "TRAFFIC CLASS × CIPHER",
    )

    print_matrix(
        df,
        "traffic_class",
        "dh_group",
        "TRAFFIC CLASS × DH GROUP",
    )

    print_matrix(
        df,
        "traffic_class",
        "pfs",
        "TRAFFIC CLASS × PFS",
    )

    print_matrix(
        df,
        "mode",
        "dh_group",
        "VPN MODE × DH GROUP",
    )

    print_matrix(
        df,
        "mode",
        "cipher_suite",
        "VPN MODE × CIPHER",
    )

    print_matrix(
        df,
        "mode",
        "pfs",
        "VPN MODE × PFS",
    )

    # ---------------------------------------------------------------
    # Full configuration combinations
    # ---------------------------------------------------------------

    print()
    print("=" * 70)
    print("TRAFFIC CLASS × FULL VPN CONFIGURATION")
    print("=" * 70)

    combinations = (
        df.groupby(
            [
                "traffic_class",
                "mode",
                "cipher_suite",
                "dh_group",
                "pfs",
            ]
        )
        .size()
        .reset_index(
            name="sessions"
        )
        .sort_values(
            [
                "traffic_class",
                "mode",
                "cipher_suite",
                "dh_group",
            ]
        )
    )

    print(
        combinations.to_string(
            index=False
        )
    )


if __name__ == "__main__":
    main()