from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

plt.style.use("seaborn-v0_8")


def prepare_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "Time" not in df.columns or "Price" not in df.columns:
        raise ValueError("DataFrame must have Time and Price columns.")
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df["Price"] = pd.to_numeric(df["Price"], errors="coerce")
    df = df.dropna(subset=["Time", "Price"]).sort_values("Time").reset_index(drop=True)
    return df


def compute_statistics(df: pd.DataFrame) -> Dict[str, Any]:
    df = prepare_df(df)
    prices = df["Price"]
    returns = prices.pct_change().dropna()
    stats = {
        "start": df["Time"].iloc[0],
        "end": df["Time"].iloc[-1],
        "count": int(len(df)),
        "mean": float(prices.mean()),
        "median": float(prices.median()),
        "std": float(prices.std()),
        "min": float(prices.min()),
        "max": float(prices.max()),
        "total_return": float((prices.iloc[-1] - prices.iloc[0]) / prices.iloc[0]) if prices.iloc[0] != 0 else None,
        "annualized_vol": float(returns.std() * np.sqrt(252)) if len(returns) > 1 else None,
    }
    return stats


def fit_linear_trend(df: pd.DataFrame) -> Tuple[float, float, pd.Timestamp]:
    df = prepare_df(df)
    t0 = df["Time"].iloc[0]
    x = (df["Time"] - t0).dt.total_seconds() / (24 * 3600)
    y = df["Price"].values
    if len(x) < 2:
        return 0.0, float(y[0]) if len(y) > 0 else 0.0, t0
    a, b = np.polyfit(x, y, 1)
    return float(a), float(b), t0


def build_analysis_figure(df: pd.DataFrame, predict_days: int = 30, ma_windows=(7, 30),
                          show_trend: bool = True, log_scale: bool = False) -> plt.Figure:
    df = prepare_df(df)
    df_ma = df.copy()
    for w in ma_windows:
        df_ma[f"MA_{w}"] = df_ma["Price"].rolling(window=w, min_periods=1).mean()

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(df_ma["Time"], df_ma["Price"], marker="o", linestyle="-", label="Price", zorder=3)

    for w in ma_windows:
        key = f"MA_{w}"
        if key in df_ma.columns:
            ax.plot(df_ma["Time"], df_ma[key], linestyle="--", label=f"MA {w}d")

    if show_trend and len(df) >= 2:
        a, b, t0 = fit_linear_trend(df)
        times = pd.date_range(df["Time"].iloc[0], df["Time"].iloc[-1], periods=200)
        xt = (times - t0).total_seconds() / (24 * 3600)
        ax.plot(times, a * xt + b, color="orange", linestyle=":", label=f"Linear trend (slope={a:.4f}/day)")

    if predict_days and predict_days > 0 and len(df) >= 2:
        a, b, t0 = fit_linear_trend(df)
        last = df["Time"].iloc[-1]
        future_dates = pd.date_range(last + pd.Timedelta(days=1), periods=predict_days, freq="D")
        xt = (future_dates - t0).total_seconds() / (24 * 3600)
        preds = a * xt + b
        ax.plot(future_dates, preds, color="purple", linestyle="--", label=f"{predict_days}-day forecast")
        ax.fill_between(future_dates, preds, alpha=0.08, color="purple")

    ax.set_xlabel("Time")
    ax.set_ylabel("Price")
    ax.set_title("Price history")
    ax.grid(True, which="both", linestyle="--", linewidth=0.5)
    if log_scale:
        ax.set_yscale("log")
    ax.legend()
    fig.tight_layout()
    return fig