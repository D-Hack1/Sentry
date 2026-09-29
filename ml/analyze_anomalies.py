from pathlib import Path
import pandas as pd


SCORES_PATH = Path("ml/evaluation/window_scores.csv")


def print_section(title):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def main():
    df = pd.read_csv(SCORES_PATH)

    print(f"Total windows: {len(df)}")
    print(f"Total sessions: {df['session_id'].nunique()}")

    # ------------------------------------------------------------
    # 1. Overall traffic-class statistics
    # ------------------------------------------------------------
    print_section("TRAFFIC CLASS")

    result = (
        df.groupby("traffic_class")
        .agg(
            windows=("anomaly_score", "size"),
            sessions=("session_id", "nunique"),
            anomalies=("is_anomaly", "sum"),
            mean_score=("anomaly_score", "mean"),
            median_score=("anomaly_score", "median"),
        )
        .reset_index()
    )

    result["anomaly_rate_%"] = (
        result["anomalies"] / result["windows"] * 100
    )

    print(result.to_string(index=False))

    # ------------------------------------------------------------
    # 2. Traffic class WITHIN each DH group
    # ------------------------------------------------------------
    print_section("TRAFFIC CLASS × DH GROUP")

    result = (
        df.groupby(["dh_group", "traffic_class"])
        .agg(
            windows=("anomaly_score", "size"),
            sessions=("session_id", "nunique"),
            anomalies=("is_anomaly", "sum"),
            mean_score=("anomaly_score", "mean"),
            median_score=("anomaly_score", "median"),
        )
        .reset_index()
    )

    result["anomaly_rate_%"] = (
        result["anomalies"] / result["windows"] * 100
    )

    print(result.to_string(index=False))

    # ------------------------------------------------------------
    # 3. Mean anomaly score matrix
    # ------------------------------------------------------------
    print_section("MEAN ANOMALY SCORE: TRAFFIC CLASS × DH GROUP")

    matrix = pd.pivot_table(
        df,
        values="anomaly_score",
        index="traffic_class",
        columns="dh_group",
        aggfunc="mean",
    )

    print(matrix.to_string())

    # ------------------------------------------------------------
    # 4. Anomaly-rate matrix
    # ------------------------------------------------------------
    print_section("ANOMALY RATE: TRAFFIC CLASS × DH GROUP")

    rate_matrix = pd.pivot_table(
        df,
        values="is_anomaly",
        index="traffic_class",
        columns="dh_group",
        aggfunc="mean",
    ) * 100

    print(rate_matrix.round(2).to_string())

    # ------------------------------------------------------------
    # 5. Session-level statistics
    # ------------------------------------------------------------
    print_section("SESSION-LEVEL FILE TRANSFER")

    session_result = (
        df.groupby(
            [
                "session_id",
                "traffic_class",
                "dh_group",
                "mode",
                "cipher_suite",
                "pfs",
            ]
        )
        .agg(
            windows=("anomaly_score", "size"),
            anomalies=("is_anomaly", "sum"),
            mean_score=("anomaly_score", "mean"),
            max_score=("anomaly_score", "max"),
        )
        .reset_index()
    )

    session_result["anomaly_rate_%"] = (
        session_result["anomalies"]
        / session_result["windows"]
        * 100
    )

    file_transfer = session_result[
        session_result["traffic_class"] == "file_transfer"
    ].sort_values("mean_score", ascending=False)

    print(file_transfer.to_string(index=False))

    # ------------------------------------------------------------
    # 6. Compare file-transfer vs everything else within DH group
    # ------------------------------------------------------------
    print_section("FILE TRANSFER vs OTHER TRAFFIC — WITHIN DH GROUP")

    df["is_file_transfer"] = (
        df["traffic_class"] == "file_transfer"
    )

    comparison = (
        df.groupby(["dh_group", "is_file_transfer"])
        .agg(
            windows=("anomaly_score", "size"),
            mean_score=("anomaly_score", "mean"),
            median_score=("anomaly_score", "median"),
            anomalies=("is_anomaly", "sum"),
        )
        .reset_index()
    )

    comparison["anomaly_rate_%"] = (
        comparison["anomalies"]
        / comparison["windows"]
        * 100
    )

    comparison["traffic_group"] = comparison["is_file_transfer"].map(
        {
            True: "file_transfer",
            False: "other_traffic",
        }
    )

    comparison = comparison.drop(columns=["is_file_transfer"])

    print(comparison.to_string(index=False))

    # ------------------------------------------------------------
    # 7. Highest-scoring windows
    # ------------------------------------------------------------
    print_section("TOP 20 ANOMALOUS WINDOWS")

    columns = [
        "session_id",
        "traffic_class",
        "dh_group",
        "mode",
        "cipher_suite",
        "pfs",
        "window_index",
        "anomaly_score",
        "is_anomaly",
    ]

    available = [c for c in columns if c in df.columns]

    top = df.sort_values(
        "anomaly_score",
        ascending=False,
    ).head(20)

    print(top[available].to_string(index=False))


if __name__ == "__main__":
    main()