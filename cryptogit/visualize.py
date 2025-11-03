
from analyse_data import build_analysis_figure
import pandas as pd


def make_analysis_figure(df: pd.DataFrame, predict_days: int = 30, ma_windows=(7, 30),
                         show_trend: bool = True, log_scale: bool = False):
    return build_analysis_figure(df, predict_days=predict_days, ma_windows=ma_windows, show_trend=show_trend, log_scale=log_scale)